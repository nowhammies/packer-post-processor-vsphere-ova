package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	debug "runtime/debug"
	"strings"
	"time"

	"github.com/cheggaaa/pb"
	vmwarecommon "github.com/hashicorp/packer/builder/vmware/common"
	"github.com/hashicorp/packer/common"
	"github.com/hashicorp/packer/helper/config"
	"github.com/hashicorp/packer/packer"
	"github.com/hashicorp/packer/template/interpolate"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vim25/types"
	"golang.org/x/net/context"
)

var builtins = map[string]string{
	"mitchellh.virtualbox": "virtualbox",
	"mitchellh.vmware":     "vmware",
}

type pluginConfig struct {
	common.PackerConfig `mapstructure:",squash"`
	UploadToVCenter     string `mapstructure:"upload_to_vcenter"`
	OutputPath          string `mapstructure:"output_path"`
	Datacenter          string `mapstructure:"datacenter"`
	Cluster             string `mapstructure:"cluster"`
	ResourcePool        string `mapstructure:"resource_pool"`
	Datastore           string `mapstructure:"datastore"`
	Host                string `mapstructure:"host"`
	Password            string `mapstructure:"password"`
	Username            string `mapstructure:"username"`
	VMFolder            string `mapstructure:"vm_folder"`
	VMNetwork           string `mapstructure:"vm_network"`
	RemoveEthernet      string `mapstructure:"remove_ethernet"`
	RemoveFloppy        string `mapstructure:"remove_floppy"`
	RemoveOpticalDrive  string `mapstructure:"remove_optical_drive"`
	VirtualHardwareVer  string `mapstructure:"virtual_hardware_version"`
	ctx                 interpolate.Context
}

// PostProcessor type
type PostProcessor struct {
	config pluginConfig
}

const jsonTrue = "true"
const jsonFalse = "false"
const vmxFalse = "FALSE"

// Configure passes config params to post processor plugin
func (p *PostProcessor) Configure(raws ...interface{}) error {
	err := config.Decode(&p.config, &config.DecodeOpts{
		Interpolate: true,
		InterpolateFilter: &interpolate.RenderFilter{
			Exclude: []string{},
		},
	}, raws...)

	if err != nil {
		return err
	}

	// Defaults
	if p.config.RemoveEthernet == "" {
		p.config.RemoveEthernet = jsonFalse
	}

	if p.config.RemoveFloppy == "" {
		p.config.RemoveFloppy = jsonFalse
	}

	if p.config.RemoveOpticalDrive == "" {
		p.config.RemoveOpticalDrive = jsonFalse
	}

	if p.config.VirtualHardwareVer == "" {
		p.config.VirtualHardwareVer = "10"
	}

	if p.config.UploadToVCenter == "" {
		p.config.UploadToVCenter = jsonTrue
	}

	// Accumulate any errors
	errs := new(packer.MultiError)

	if _, err := exec.LookPath("ovftool"); err != nil {
		errs = packer.MultiErrorAppend(
			errs, fmt.Errorf("ovftool not found: %s", err))
	}

	if p.config.UploadToVCenter != jsonFalse {
		// First define all our templatable parameters that are _required_
		templates := map[string]*string{
			"datacenter": &p.config.Datacenter,
			"host":       &p.config.Host,
			"password":   &p.config.Password,
			"username":   &p.config.Username,
			"datastore":  &p.config.Datastore,
			"vm_folder":  &p.config.VMFolder,
		}

		for key, ptr := range templates {
			if *ptr == "" {
				errs = packer.MultiErrorAppend(
					errs, fmt.Errorf("%s must be set", key))
			}
		}

		if len(errs.Errors) > 0 {
			return errs
		}
	} else {
		if p.config.OutputPath == "" {
			return fmt.Errorf("%s must be set", "output_path")
		}
	}
	return nil
}

// PostProcess fixes hardware defs in ova/ovf to match VMware requirements and uploads ova/ovf to vCenter
func (p *PostProcessor) PostProcess(ui packer.Ui, artifact packer.Artifact) (packer.Artifact, bool, error) {
	if _, ok := builtins[artifact.BuilderId()]; !ok {
		return nil, false, fmt.Errorf("Unknown artifact type, can't build box: %s", artifact.BuilderId())
	}

	ova := ""
	vmx := ""
	vmdk := ""
	for _, path := range artifact.Files() {
		if strings.HasSuffix(path, ".ova") {
			ova = path
			break
		} else if strings.HasSuffix(path, ".vmx") {
			vmx = path
		} else if strings.HasSuffix(path, ".vmdk") {
			vmdk = path
		}
	}

	if ova == "" && (vmx == "" || vmdk == "") {
		return nil, false, fmt.Errorf("ERROR: Neither OVA or VMX/VMDK were found")
	}

	if ova != "" {
		// Sweet, we've got an OVA, Now it's time to make that baby something we can work with.
		command := exec.Command(
			"ovftool", "--lax", "--allowAllExtraConfig",
			fmt.Sprintf("--extraConfig:ethernet0.networkName=%s", p.config.VMNetwork),
			ova,
			fmt.Sprintf("%s.vmx", strings.TrimSuffix(ova, ".ova")))

		var ovftoolOut bytes.Buffer
		command.Stdout = &ovftoolOut
		if err := command.Run(); err != nil {
			return nil, false, fmt.Errorf("Failed: %s\nStdout: %s", err, ovftoolOut.String())
		}

		ui.Message(fmt.Sprintf("%s", ovftoolOut.String()))

		vmdk = fmt.Sprintf("%s-disk1.vmdk", strings.TrimSuffix(ova, ".ova"))
		vmx = fmt.Sprintf("%s.vmx", strings.TrimSuffix(ova, ".ova"))
	}

	if err := fixVirtualHardware(p.config, vmx, ui); err != nil {
		return nil, false, err
	}

	if p.config.UploadToVCenter == jsonTrue {
		if err := uploadToVCenter(ui, p.config, vmdk, vmx); err != nil {
			return nil, false, err
		}

		return artifact, false, nil
	}

	ui.Message(fmt.Sprintf("Moving %s, %s to %s", vmx, vmdk, p.config.OutputPath))

	newVmx, err := moveToOutputPath(p.config, vmx)
	if err != nil {
		return artifact, false, err
	}

	newVmdk, err := moveToOutputPath(p.config, vmdk)
	if err != nil {
		return artifact, false, err
	}

	newArtifact, err := NewArtifact("vsphere-vmx", []string{newVmx, newVmdk})
	if err != nil {
		return artifact, false, err
	}

	return newArtifact, false, nil
}

func fixVirtualHardware(config pluginConfig, vmx string, ui packer.Ui) error {
	devices := [][]string{
		[]string{config.RemoveEthernet, "ethernet0", "ethernet0.", "ethernet0.present"},
		[]string{config.RemoveOpticalDrive, "floppy", "floppy0.", "floppy0.present"},
		[]string{config.RemoveOpticalDrive, "optical drive", "ide1:0.file", "ide1:0.present"}}

	for _, deviceDef := range devices {
		if deviceDef[0] == jsonTrue {
			if err := removeDevice(ui, deviceDef[1:], vmx); err != nil {
				return fmt.Errorf("Removing %s from VMX failed!", deviceDef[0])
			}
		}
	}

	if config.VirtualHardwareVer != "" {
		if err := setVHardwareVersion(ui, vmx, config.VirtualHardwareVer); err != nil {
			return fmt.Errorf("Setting the Virtual Hardware Version in VMX failed!")
		}
	}
	return nil
}

func removeDevice(ui packer.Ui, deviceDef []string, vmx string) error {
	deviceName := deviceDef[0]
	prefix := deviceDef[1]
	deviceID := deviceDef[2]

	ui.Message(fmt.Sprintf("Removing %s from %s", deviceName, vmx))

	vmxData, err := vmwarecommon.ReadVMX(vmx)
	if err != nil {
		return err
	}
	for k := range vmxData {
		if strings.HasPrefix(k, prefix) {
			delete(vmxData, k)
		}
	}
	vmxData[deviceID] = vmxFalse
	if err := vmwarecommon.WriteVMX(vmx, vmxData); err != nil {
		return err
	}
	return nil
}

func setVHardwareVersion(ui packer.Ui, vmx string, hwversion string) error {
	ui.Message(fmt.Sprintf("Setting the hardware version in the vmx to version '%s'", hwversion))

	vmxContent, err := ioutil.ReadFile(vmx)
	if err != nil {
		return err
	}

	lines := strings.Split(string(vmxContent), "\n")
	for i, line := range lines {
		if strings.Contains(line, "virtualhw.version") {
			lines[i] = fmt.Sprintf("virtualhw.version = \"%s\"", hwversion)
		}
	}
	output := strings.Join(lines, "\n")
	err = ioutil.WriteFile(vmx, []byte(output), 0644)
	if err != nil {
		return err
	}

	return nil
}

func moveToOutputPath(config pluginConfig, srcPath string) (string, error) {
	if _, err := os.Stat(config.OutputPath); os.IsNotExist(err) {
		err := os.Mkdir(config.OutputPath, 0755)
		if err != nil {
			return "", err
		}
	}

	pathSplit := strings.Split(srcPath, "/")
	destPath := fmt.Sprintf("%s/%s", config.OutputPath, pathSplit[len(pathSplit)-1])

	if err := os.Rename(srcPath, destPath); err != nil {
		return "", err
	}

	return destPath, nil
}

func uploadToVCenter(ui packer.Ui, config pluginConfig, vmdk string, vmx string) error {
	ui.Message(fmt.Sprintf("Uploading %s and %s to Datastore %s on host %s", vmdk, vmx, config.Datastore, config.Host))

	clonerequired := false
	if config.RemoveEthernet == jsonFalse || config.RemoveFloppy == jsonFalse || config.RemoveOpticalDrive == jsonFalse {
		clonerequired = true
	}

	splitString := strings.Split(vmdk, "/")
	vmdkDestPath := fmt.Sprintf("folder/%s/%s", config.VMFolder, splitString[len(splitString)-1])

	splitString = strings.Split(vmx, "/")
	vmxDestPath := fmt.Sprintf("folder/%s/%s", config.VMFolder, splitString[len(splitString)-1])

	if err := uploadFileToStorage(ui, config, vmdk, vmdkDestPath); err != nil {
		return fmt.Errorf("Failed: %s", err)
	}

	ui.Message(fmt.Sprintf("Uploaded %s", vmdk))

	if err := uploadFileToStorage(ui, config, vmx, vmxDestPath); err != nil {
		return fmt.Errorf("Failed: %s", err)
	}

	ui.Message(fmt.Sprintf("Uploaded %s", vmx))

	if err := registerVMTemplate(ui, config, vmx, clonerequired); err != nil {
		return fmt.Errorf("Failed: %s", err)
	}

	ui.Message("Uploaded and registered to VMware")
	return nil
}

func uploadFileToStorage(ui packer.Ui, config pluginConfig, file string, fileDestPath string) error {

	url := fmt.Sprintf("https://%s:%s@%s/%s?dcPath=%s&dsName=%s",
		url.QueryEscape(config.Username),
		url.QueryEscape(config.Password),
		config.Host,
		fileDestPath,
		config.Datacenter,
		config.Datastore)

	data, err := os.Open(file)
	if err != nil {
		return err
	}
	defer data.Close()

	fileInfo, err := data.Stat()
	if err != nil {
		return err
	}

	bar := pb.New64(fileInfo.Size()).SetUnits(pb.U_BYTES)
	bar.ShowSpeed = true
	bar.Callback = ui.Message
	bar.RefreshRate = time.Second * 5
	bar.SetWidth(40)
	reader := bar.NewProxyReader(data)

	req, err := http.NewRequest("PUT", url, reader)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = fileInfo.Size()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	bar.Start()
	res, err := client.Do(req)
	bar.Finish()

	if err != nil {
		return err
	}

	defer res.Body.Close()

	return nil
}

func registerVMTemplate(ui packer.Ui, config pluginConfig, vmx string, clonerequired bool) error {

	sdkURL, err := url.Parse(fmt.Sprintf("https://%s:%s@%s/sdk",
		url.QueryEscape(config.Username),
		url.QueryEscape(config.Password),
		config.Host))
	if err != nil {
		return err
	}

	client, err := govmomi.NewClient(context.TODO(), sdkURL, true)
	if err != nil {
		return err
	}

	finder := find.NewFinder(client.Client, false)
	datacenter, err := finder.DefaultDatacenter(context.TODO())
	if err != nil {
		return err
	}
	finder.SetDatacenter(datacenter)

	folders, err := datacenter.Folders(context.TODO())
	if err != nil {
		return err
	}

	resourcePool, err := getResourcePool(finder, config, client)
	if err != nil {
		return err
	}

	splitString := strings.Split(vmx, "/")
	last := splitString[len(splitString)-1]
	vmName := strings.TrimSuffix(last, ".vmx")

	datastoreString := fmt.Sprintf("[%s] %s/%s.vmx", config.Datastore, config.VMFolder, vmName)

	ui.Message(fmt.Sprintf("Registering %s from %s", vmName, datastoreString))
	task, err := folders.VmFolder.RegisterVM(context.TODO(), datastoreString, vmName, false, resourcePool, nil)
	if err != nil {
		return err
	}

	if _, err := task.WaitForResult(context.TODO(), nil); err != nil {
		return err
	}
	ui.Message(fmt.Sprintf("Registered VM %s", vmName))

	vm, err := finder.VirtualMachine(context.TODO(), vmName)
	if err != nil {
		return err
	}

	rpRef := resourcePool.Reference()

	if clonerequired {
		cloneSpec := types.VirtualMachineCloneSpec{
			Location: types.VirtualMachineRelocateSpec{
				Pool: &rpRef,
			},
		}

		cloneVMName := fmt.Sprintf("%s-vm", vmName)

		ui.Message(fmt.Sprintf("Cloning VM %s", cloneVMName))
		task, err := vm.Clone(context.TODO(), folders.VmFolder, cloneVMName, cloneSpec)
		if err != nil {
			return err
		}

		if _, err := task.WaitForResult(context.TODO(), nil); err != nil {
			return err
		}

		clonedVM, err := finder.VirtualMachine(context.TODO(), cloneVMName)
		if err != nil {
			return err
		}

		ui.Message(fmt.Sprintf("Powering on %s", cloneVMName))
		task, err = clonedVM.PowerOn(context.TODO())
		if err != nil {
			return err
		}

		_, err = task.WaitForResult(context.TODO(), nil)
		if err != nil {
			return err
		}

		ui.Message(fmt.Sprintf("Powered on %s", cloneVMName))

		timeout := time.After(5 * time.Minute)
		tick := time.Tick(500 * time.Millisecond)

	LoopWaitForVMToolsRunning:
		for {
			select {
			case <-timeout:
				task, err = clonedVM.PowerOff(context.TODO())
				if err != nil {
					return err
				}
				_, err = task.WaitForResult(context.TODO(), nil)
				if err != nil {
					return err
				}
				return fmt.Errorf("Timed out while waiting for VM Tools to be recogonized")
			case <-tick:
				running, err := clonedVM.IsToolsRunning(context.TODO())
				if err != nil {
					return err
				}
				if running {
					break LoopWaitForVMToolsRunning
				}
			}
		}

		ui.Message(fmt.Sprintf("Powering off %s", cloneVMName))
		task, err = clonedVM.PowerOff(context.TODO())

		if err != nil {
			return err
		}

		_, err = task.WaitForResult(context.TODO(), nil)

		if err != nil {
			return err
		}
		ui.Message(fmt.Sprintf("Powered off %s", cloneVMName))

		ui.Message(fmt.Sprintf("Marking as template %s", cloneVMName))
		err = clonedVM.MarkAsTemplate(context.TODO())

		if err != nil {
			return err
		}

		ui.Message(fmt.Sprintf("Destroying %s", cloneVMName))
		task, err = vm.Destroy(context.TODO())
		if err != nil {
			return err
		}

		_, err = task.WaitForResult(context.TODO(), nil)

		if err != nil {
			return err
		}
		ui.Message(fmt.Sprintf("Destroyed %s", cloneVMName))
	} else {
		ui.Message(fmt.Sprintf("Marking as template %s", vmName))
		err = vm.MarkAsTemplate(context.TODO())

		if err != nil {
			return err
		}
		ui.Message(fmt.Sprintf("%s is now a template", vmName))
	}

	return nil
}

func getResourcePool(finder *find.Finder, config pluginConfig, client *govmomi.Client) (*object.ResourcePool, error) {
	var resourcePool *object.ResourcePool
	var err error

	if config.ResourcePool != "" {
		resourcePool, err = finder.ResourcePool(context.TODO(), config.ResourcePool)
	} else if config.Cluster != "" {
		var cluster *object.ClusterComputeResource

		cluster, err = finder.ClusterComputeResource(context.TODO(), config.Cluster)
		if err != nil {
			debug.PrintStack()
			return nil, err
		}
		resourcePool, err = cluster.ResourcePool(context.TODO())
	} else {
		resourcePool, err = finder.DefaultResourcePool(context.TODO())
	}

	if err != nil {
		debug.PrintStack()
		return nil, err
	}

	return resourcePool, nil
}

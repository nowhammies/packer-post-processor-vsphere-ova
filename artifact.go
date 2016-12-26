package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const BuilderId = "banno.post-processor.vsphere"

type Artifact struct {
	name  string
	files []string
}

func NewArtifact(name string, files []string) (*Artifact, error) {
	artifact := &Artifact{
		name:  name,
		files: files,
	}

	for _, f := range files {
		globfiles, err := filepath.Glob(f)
		if err != nil {
			return nil, err
		}
		for _, gf := range globfiles {
			if _, err := os.Stat(gf); err != nil {
				return nil, err
			}
			artifact.files = append(artifact.files, gf)
		}
	}
	return artifact, nil
}

func (*Artifact) BuilderId() string {
	return BuilderId
}

func (a *Artifact) Files() []string {
	return a.files
}

func (a *Artifact) Id() string {
	return ""
}

func (a *Artifact) String() string {
	return fmt.Sprintf("%s", a.name)
}

func (a *Artifact) State(name string) interface{} {
	return nil
}

func (a *Artifact) Destroy() error {
	for _, f := range a.files {
		err := os.RemoveAll(f)
		if err != nil {
			return err
		}
	}
	return nil
}

package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
)

func getFilePathsIn(dirpath string) (filepaths []string, err error) {
	dir, err := os.Open(dirpath)
	if err != nil {
		return
	}

	fi, err := dir.Stat()
	if err != nil {
		return
	}

	switch mode := fi.Mode(); {
	case mode.IsDir():
		files, _ := ioutil.ReadDir(dirpath)
		for _, f := range files {
			path := path.Join(dirpath, f.Name())
			filepaths = append(filepaths, path)
		}
	case mode.IsRegular():
		err = errors.New(fmt.Sprintf("Error cannot iterate directory: %s", dirpath))
		break
	}

	return
}

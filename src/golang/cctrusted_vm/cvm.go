package vmsdk

import (
	"crypto/sha512"
	"errors"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cc-api/cc-trusted-api/common/golang/cctrusted_base"
)

const (
	TSM_PREFIX = "/sys/kernel/config/tsm/report"
	TSM_ENV    = "TSM_REPORT"
)

type Device interface {
	ProbeDevice() error
	Report(nonce, userData string, extraArgs map[string]any) (cctrusted_base.CcReport, error)
	Name() string
	CCType() cctrusted_base.CC_Type
	Version() cctrusted_base.DeviceVersion
}

type GenericDevice struct {
	Device
}

func (d *GenericDevice) Report(nonce, userData string, extraArgs map[string]any) (cctrusted_base.CcReport, error) {
	var err error
	var tempdir string
	var dirExist bool

	if _, err = os.Stat(TSM_PREFIX); os.IsNotExist(err) {
		return cctrusted_base.CcReport{}, errors.New("Configfs TSM is not supported in the current environment.")
	}

	hasher := sha512.New()
	if nonce != "" {
		hasher.Write([]byte(nonce))
	}
	if userData != "" {
		hasher.Write([]byte(userData))
	}
	reportData := []byte(hasher.Sum(nil))

	if os.Getenv(TSM_ENV) != "" {
		if _, err = os.Stat(os.Getenv(TSM_ENV)); !os.IsNotExist(err) {
			tempdir = os.Getenv(TSM_ENV)
			dirExist = true
		}
	}

	if tempdir == "" {
		tempdir, err = os.MkdirTemp(TSM_PREFIX, "report_")
		if err != nil {
			return cctrusted_base.CcReport{}, errors.New("Failed to init entry in Configfs TSM.")
		}
		dirExist = false
	}

	var outblob, provider, auxblob []byte
	var preGeneration, generation int

	// Check the original value of generation to guarantee report freshness
	if _, err = os.Stat(filepath.Join(tempdir, "generation")); !os.IsNotExist(err) {
		rawGeneration, err := os.ReadFile(filepath.Join(tempdir, "generation"))
		if err != nil {
			return cctrusted_base.CcReport{}, errors.New("Failed to get generation info.")
		}
		preGeneration, _ = strconv.Atoi(string(rawGeneration))
	} else {
		return cctrusted_base.CcReport{}, errors.New("Failed to get generation info.")
	}

	if _, err = os.Stat(filepath.Join(tempdir, "inblob")); !os.IsNotExist(err) {
		err = os.WriteFile(filepath.Join(tempdir, "inblob"), reportData, 0400)
		if err != nil {
			return cctrusted_base.CcReport{}, errors.New("Failed to push report data into inblob.")
		}
	} else {
		return cctrusted_base.CcReport{}, errors.New("Failed to get inblob info.")
	}

	if v, ok := extraArgs["privilege"]; ok {
		if val, ok := v.(int); ok {
			err = os.WriteFile(filepath.Join(tempdir, "privlevel"), []byte(strconv.Itoa(val)), 0400)
			if err != nil {
				return cctrusted_base.CcReport{}, errors.New("Failed to push privilege data to privlevel file.")
			}
		}
	}

	if _, err = os.Stat(filepath.Join(tempdir, "outblob")); !os.IsNotExist(err) {
		outblob, err = os.ReadFile(filepath.Join(tempdir, "outblob"))
		if err != nil {
			return cctrusted_base.CcReport{}, errors.New("Failed to get outblob.")
		}
	} else {
		return cctrusted_base.CcReport{}, errors.New("Failed to get outblob info.")
	}

	if _, err = os.Stat(filepath.Join(tempdir, "generation")); !os.IsNotExist(err) {
		rawGeneration, err := os.ReadFile(filepath.Join(tempdir, "generation"))
		if err != nil {
			return cctrusted_base.CcReport{}, errors.New("Failed to get generation info.")
		}
		generation, _ = strconv.Atoi(string(rawGeneration))
		// Check if the outblob has been corrupted during file open
		if generation-preGeneration != 1 {
			return cctrusted_base.CcReport{}, errors.New("Found corrupted generation.")
		}
	} else {
		return cctrusted_base.CcReport{}, errors.New("Failed to get generation info.")
	}

	if _, err = os.Stat(filepath.Join(tempdir, "provider")); !os.IsNotExist(err) {
		provider, err = os.ReadFile(filepath.Join(tempdir, "provider"))
		if err != nil {
			return cctrusted_base.CcReport{}, errors.New("Failed to get provider info.")
		}
	} else {
		return cctrusted_base.CcReport{}, errors.New("Failed to get provider info.")
	}

	if _, err = os.Stat(filepath.Join(tempdir, "auxblob")); !os.IsNotExist(err) {
		auxblob, err = os.ReadFile(filepath.Join(tempdir, "auxblob"))
		if err != nil {
			return cctrusted_base.CcReport{}, errors.New("Failed to get auxblob info.")
		}
	}

	if dirExist {
		os.RemoveAll(tempdir)
	}

	return cctrusted_base.CcReport{
		Outblob:    outblob,
		Provider:   string(provider),
		Generation: generation,
		Auxblob:    auxblob,
	}, nil
}

type EventRecorder interface {
	ProbeRecorder() error
	FullEventLog() ([]byte, error)
}

type CVMContext struct {
	VMType  cctrusted_base.CC_Type
	Version cctrusted_base.DeviceVersion
}

type ConfidentialVM interface {
	Probe() error
	CVMContext() CVMContext
	MaxImrIndex() int
	DefaultAlgorithm() cctrusted_base.TCG_ALG
	Device
	EventRecorder
	cctrusted_base.IMARecorder
}

type CVMInitArgs struct {
	// RedirectedAcpiTableFile is the alternative
	// of the original `DEFAULT_ACPI_TABLE_FILE`, if which
	// can not be accessed
	RedirectedAcpiTableFile string
	// RedirectedAcpiTableDataFile is the alternative
	// of the original `DEFAULT_ACPI_TABLE_DATA_FILE`, if which
	// can not be accessed
	RedirectedAcpiTableDataFile string
}

type CVMInitFunc func(*CVMInitArgs) (ConfidentialVM, error)

var cvmInitFuncs []CVMInitFunc

func RegisterCVMInitFunc(fn CVMInitFunc) {
	cvmInitFuncs = append(cvmInitFuncs, fn)
}

func GetCVMInstance(args *CVMInitArgs) (ConfidentialVM, error) {
	for _, fn := range cvmInitFuncs {
		cvm, err := fn(args)
		if err != nil {
			continue
		}
		return cvm, nil
	}
	return nil, errors.New("no available confidential vm")
}

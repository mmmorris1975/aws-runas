package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// DefaultEnvLoader creates a default EnvLoader type to read configuration and credentials from environment variables.
var DefaultEnvLoader = new(envLoader)

type envLoader bool

// Config is the implementation of the Loader interface.  The profile and sources arguments are ignored, and the value
// is returned via delegation to the EnvConfig() method.
func (l *envLoader) Config(string, ...interface{}) (*AwsConfig, error) {
	return l.EnvConfig()
}

// Credentials is the implementation of the Loader interface.  The profile and sources arguments are ignored, and the value
// is returned via delegation to the EnvCredentials() method.
func (l *envLoader) Credentials(string, ...interface{}) (*AwsCredentials, error) {
	return l.EnvCredentials()
}

// Config loads fields in the AwsConfig type which support environment variables.
func (l *envLoader) EnvConfig() (*AwsConfig, error) {
	c := new(AwsConfig)
	if err := resolveEnv(c); err != nil {
		return nil, err
	}
	return c, nil
}

// Credentials loads SAML and or Web Identity (OIDC) passwords from environment variables.
func (l *envLoader) EnvCredentials() (*AwsCredentials, error) {
	c := new(AwsCredentials)
	if err := resolveEnv(c); err != nil {
		return nil, err
	}
	return c, nil
}

func resolveEnv(t interface{}) error {
	tv := reflect.ValueOf(t)
	if tv.Kind() != reflect.Ptr {
		return errors.New("not a pointer")
	}
	tt := tv.Elem().Type()

	for i := 0; i < tt.NumField(); i++ {
		ft := tt.Field(i)
		if envTag, ok := ft.Tag.Lookup("env"); ok {
			val := getEnvVar(envTag)
			if err := setVal(tv.Elem().Field(i), val); err != nil {
				return err
			}
		}
	}
	return nil
}

func getEnvVar(tag string) string {
	// loop through tag value of potential env vars to use, return the 1st one which is set
	for _, envVar := range strings.Split(tag, `,`) {
		if envVal, ok := os.LookupEnv(envVar); ok && len(envVal) > 0 {
			return envVal
		}
	}
	return ""
}

func setVal(field reflect.Value, value string) error {
	var err error

	switch field.Type().Kind() {
	case reflect.String:
		field.SetString(value)
	// case reflect.Bool:
	// 	 b, err := strconv.ParseBool(value)
	// 	 if err != nil {
	//		 b = false
	//	 }
	//	 field.SetBool(b)
	// case reflect.Complex64, reflect.Complex128:
	//	 cplx := complex128(0)
	//	 if len(value) > 0 {
	//		cplx, err = strconv.ParseComplex(value, 128)
	//		if err != nil {
	//			return err
	//		}
	//	 }
	//	 field.SetComplex(cplx)
	// case reflect.Float32, reflect.Float64:
	//	fl := float64(0)
	//	if len(value) > 0 {
	//		fl, err = strconv.ParseFloat(value, 64)
	//		if err != nil {
	//			return err
	//		}
	//	}
	//	field.SetFloat(fl)
	// case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32:
	//	i := int64(0)
	//	if len(value) > 0 {
	//		i, err = strconv.ParseInt(value, 0, 64)
	//		if err != nil {
	//			return err
	//		}
	//	}
	//	field.SetInt(i)
	case reflect.Int64:
		i := int64(0)
		if len(value) > 0 {
			// could be an actual Int64, or an alias ... like time.Duration
			i, err = strconv.ParseInt(value, 0, 64)
			if err != nil {
				d, err := time.ParseDuration(value)
				if err != nil {
					return err
				}
				i = int64(d)
			}
		}
		field.SetInt(i)
	// case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
	//	ui := uint64(0)
	//	if len(value) > 0 {
	//		// Uint8 may break handling of byte values
	//		ui, err = strconv.ParseUint(value, 0, 64)
	//		if err != nil {
	//			return err
	//		}
	//	}
	//	field.SetUint(ui)
	default:
		return fmt.Errorf("unknown type: %s", field.Type().Kind().String())
	}
	return nil
}

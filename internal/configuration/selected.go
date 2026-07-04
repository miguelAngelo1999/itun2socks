package configuration

import (
	"fmt"
)

func GetSelectedId(bucket string) (string, error) {
	c, err := Read()
	if err != nil {
		return "", err
	}
	if bucket == "rule" {
		return c.Selected.Rule, nil
	} else if bucket == "proxy" {
		return c.Selected.Proxy, nil
	}
	return "", fmt.Errorf("error gettting selected id,type:%v err: invalid field", bucket)
}

func GetPreviousProxyId() string {
	c, err := Read()
	if err != nil {
		return ""
	}
	return c.Selected.PreviousProxy
}

func SetSelectedId(bucket, id string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	var previousId string
	if bucket == "rule" {
		c.Selected.Rule = id
	} else if bucket == "proxy" {
		previousId = c.Selected.Proxy
		c.Selected.Proxy = id
		// Track previous proxy for expiry auto-fallback priority
		if previousId != "" && previousId != id {
			c.Selected.PreviousProxy = previousId
		}
	} else {
		return fmt.Errorf("error seting selected id,type:%v err: invalid field", bucket)
	}
	err = Write(c)
	if err != nil {
		return err
	}
	// Clear one-time password on the previous proxy after saving selection
	if bucket == "proxy" && previousId != "" && previousId != id {
		_ = ClearOneTimePassword(previousId)
	}
	return nil
}

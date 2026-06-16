package configuration

import "fmt"

// GetSslInspectionSettings returns the current SSL inspection configuration.
func GetSslInspectionSettings() (SslInspectionCfg, error) {
c, err := Read()
if err != nil {
return SslInspectionCfg{}, err
}
return c.SslInspection, nil
}

// SetSslInspectionEnabled enables or disables SSL inspection globally.
func SetSslInspectionEnabled(enabled bool) error {
c, err := Read()
if err != nil {
return err
}
c.SslInspection.Enabled = enabled
return Write(c)
}

// GetInspectionList returns the current list of inspection entries.
func GetInspectionList() ([]SslInspectionEntry, error) {
c, err := Read()
if err != nil {
return nil, err
}
return c.SslInspection.InspectionList, nil
}

// AddInspectionEntry appends a new entry with Enabled=true if the pattern is not already present.
func AddInspectionEntry(pattern string) error {
c, err := Read()
if err != nil {
return err
}
for _, entry := range c.SslInspection.InspectionList {
if entry.Pattern == pattern {
// Already present — nothing to do.
return nil
}
}
c.SslInspection.InspectionList = append(c.SslInspection.InspectionList, SslInspectionEntry{
Pattern: pattern,
Enabled: true,
})
return Write(c)
}

// RemoveInspectionEntry removes the entry matching the given pattern.
func RemoveInspectionEntry(pattern string) error {
c, err := Read()
if err != nil {
return err
}
updated := c.SslInspection.InspectionList[:0]
for _, entry := range c.SslInspection.InspectionList {
if entry.Pattern != pattern {
updated = append(updated, entry)
}
}
c.SslInspection.InspectionList = updated
return Write(c)
}

// ToggleInspectionEntry flips the Enabled flag on the entry matching the given pattern.
func ToggleInspectionEntry(pattern string) error {
c, err := Read()
if err != nil {
return err
}
for i, entry := range c.SslInspection.InspectionList {
if entry.Pattern == pattern {
c.SslInspection.InspectionList[i].Enabled = !entry.Enabled
return Write(c)
}
}
return fmt.Errorf("inspection entry not found: %s", pattern)
}

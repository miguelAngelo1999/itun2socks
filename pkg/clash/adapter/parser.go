package adapter

import (
	"fmt"

	"github.com/igoogolx/itun2socks/pkg/clash/adapter/outbound"
	"github.com/igoogolx/itun2socks/pkg/clash/common/structure"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
)

func ParseProxy(mapping map[string]any) (C.Proxy, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
	proxyType, existType := mapping["type"].(string)
	if !existType {
		return nil, fmt.Errorf("missing type")
	}

	// PAC-only proxy: no fixed upstream server, a PAC URL supplies the upstream
	// per connection. Detected by an empty server + a non-empty pacUrl. This is
	// checked BEFORE the type switch so the normal server-based paths stay
	// byte-for-byte unchanged (zero regression on the PAC-gates-a-server path,
	// which keeps a real server and is handled by the switch below).
	server, _ := mapping["server"].(string)
	pacUrl, _ := mapping["pacUrl"].(string)
	if server == "" && pacUrl != "" {
		id, _ := mapping["id"].(string)
		user, _ := mapping["username"].(string)
		pass, _ := mapping["password"].(string)
		name, _ := mapping["name"].(string)
		dyn := outbound.NewPacDynamic(outbound.PacDynamicOption{
			Name:     name,
			ProxyId:  id,
			UserName: user,
			Password: pass,
		})
		return NewProxy(dyn), nil
	}

	var (
		proxy C.ProxyAdapter
		err   error
	)
	switch proxyType {
	case "ss":
		ssOption := &outbound.ShadowSocksOption{}
		err = decoder.Decode(mapping, ssOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowSocks(*ssOption)
	case "ssr":
		ssrOption := &outbound.ShadowSocksROption{}
		err = decoder.Decode(mapping, ssrOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowSocksR(*ssrOption)
	case "socks5":
		socksOption := &outbound.Socks5Option{}
		err = decoder.Decode(mapping, socksOption)
		if err != nil {
			break
		}
		proxy = outbound.NewSocks5(*socksOption)
	case "http":
		httpOption := &outbound.HttpOption{}
		err = decoder.Decode(mapping, httpOption)
		if err != nil {
			break
		}
		proxy = outbound.NewHttp(*httpOption)
	case "vless":
		fallthrough
	case "vmess":
		vmessOption := &outbound.VmessOption{
			HTTPOpts: outbound.HTTPOptions{
				Method: "GET",
				Path:   []string{"/"},
			},
		}
		err = decoder.Decode(mapping, vmessOption)
		if err != nil {
			break
		}
		if proxyType == "vless" {
			proxy, err = outbound.NewVless(*vmessOption)
		} else {
			proxy, err = outbound.NewVmess(*vmessOption)
		}
	case "snell":
		snellOption := &outbound.SnellOption{}
		err = decoder.Decode(mapping, snellOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSnell(*snellOption)
	case "trojan":
		trojanOption := &outbound.TrojanOption{}
		err = decoder.Decode(mapping, trojanOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTrojan(*trojanOption)
	default:
		return nil, fmt.Errorf("unsupport proxy type: %s", proxyType)
	}

	if err != nil {
		return nil, err
	}

	return NewProxy(proxy), nil
}

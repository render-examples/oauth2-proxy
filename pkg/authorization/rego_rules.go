package authorization

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/open-policy-agent/opa/rego"
)

type AuthInput struct {
	Request *Request
}

type Request struct {
	Method string
	URL    *url.URL
	IP     net.IP
}

type regoRuleSet struct {
	query        rego.PreparedEvalQuery
	clientIPFunc func(*http.Request) net.IP
}

func (r *regoRuleSet) newRequest(req *http.Request) *Request {
	if req == nil {
		return nil
	}

	return &Request{
		Method: req.Method,
		URL:    req.URL,
		IP:     r.getClientIP(req),
	}
}

func (r *regoRuleSet) getClientIP(req *http.Request) net.IP {
	if r.clientIPFunc == nil {
		return net.IP{}
	}
	return r.clientIPFunc(req)
}

func (r *regoRuleSet) Matches(req *http.Request) AuthorizationPolicy {
	results, err := r.query.Eval(req.Context(), rego.EvalInput(AuthInput{
		Request: r.newRequest(req),
	}))
	if err != nil {
		return DenyPolicy
	}
	for _, result := range results {
		for _, binding := range result.Bindings {
			if allowed, ok := binding.(bool); ok && allowed {
				return AllowPolicy
			} else if ok && !allowed {
				return DenyPolicy
			}
		}
	}
	return NonePolicy
}

func NewRegoRuleSet(requestRules options.RequestRules, getClientIPFunc func(*http.Request) net.IP) (RuleSet, error) {
	builders := []func(*rego.Rego){}
	for i, rule := range requestRules {
		bs, err := newRegoRule(rule, fmt.Sprintf("rule%s", intToLetters(i+1)))
		if err != nil {
			return nil, err
		}
		builders = append(builders, bs...)
	}

	r := rego.New(builders...)

	query, err := r.PrepareForEval(context.TODO())
	if err != nil {
		return nil, err
	}

	return &regoRuleSet{
		query:        query,
		clientIPFunc: getClientIPFunc,
	}, nil
}

func newRegoRule(authRule options.AuthorizationRule, packageName string) ([]func(*rego.Rego), error) {
	t, err := template.New("").Parse(`
package {{.PackageName}}

allow {
{{ if .Methods }}
  {{.Methods}}
{{ end }}
{{if .Path}}
  {{.Path}}
{{ end }}
{{if .IPs}}
  {{.IPs}}
{{ end }}
}
`)
	if err != nil {
		return nil, err
	}

	var data = struct {
		PackageName string
		Methods     string
		Path        string
		IPs         string
	}{
		PackageName: packageName,
		Methods:     getRegoMethods(authRule.Methods),
		Path:        getRegoPath(authRule.Path),
		IPs:         getRegoIPs(authRule.IPs),
	}

	moduleText := bytes.NewBuffer([]byte{})
	if err := t.Execute(moduleText, data); err != nil {
		return nil, err
	}

	return []func(*rego.Rego){
		rego.Module(packageName, moduleText.String()),
		rego.Query(fmt.Sprintf("allow = data.%s.allow", packageName)),
	}, nil
}

func getRegoMethods(methods []string) string {
	switch len(methods) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf(`input.Request.Method == "%s"`, strings.ToUpper(methods[0]))
	default:
		quotedMethods := []string{}
		for _, method := range methods {
			quotedMethods = append(quotedMethods, fmt.Sprintf("input.Request.Method == %q", strings.ToUpper(method)))
		}
		return fmt.Sprintf("any([%s])", strings.Join(quotedMethods, ","))
	}
}

func getRegoPath(path string) string {
	if len(path) == 0 {
		return ""
	}
	return fmt.Sprintf(`regex.match("%s", input.Request.URL.Path)`, path)
}

func getRegoIPs(cidrs []string) string {
	switch len(cidrs) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf(`net.cidr_contains("%s", input.Request.IP)`, cidrs[0])
	default:
		quotedCidrs := []string{}
		for _, cidr := range cidrs {
			quotedCidrs = append(quotedCidrs, fmt.Sprintf("%q", cidr))
		}
		return fmt.Sprintf("count(net.cidr_contains_matches([%s], input.Request.IP)) > 0", strings.Join(quotedCidrs, ","))
	}
}

func intToLetters(number int) (letters string) {
	number--
	if firstLetter := number / 26; firstLetter > 0 {
		letters += intToLetters(firstLetter)
		letters += string('A' + rune(number%26))
	} else {
		letters += string('A' + rune(number))
	}

	return
}

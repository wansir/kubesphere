/*
 *
 * Copyright 2019 The KubeSphere Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * /
 */

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/go-ldap/ldap"
	log "github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"io"
	"io/ioutil"
	pool "kubesphere.io/kubesphere/pkg/simple/client/ldap"
	"kubesphere.io/kubesphere/pkg/utils/signals"
	"net/http"
	"strconv"
	"strings"
)

type Proxy struct {
}

func NewProxy() *Proxy { return &Proxy{} }

func (p *Proxy) ServeHTTP(wr http.ResponseWriter, r *http.Request) {
	var resp *http.Response
	var err error
	var req *http.Request
	client := &http.Client{}

	req, err = http.NewRequest(r.Method, "http://127.0.0.1:9090"+r.RequestURI, r.Body)
	for name, value := range r.Header {
		req.Header.Set(name, value[0])
	}

	if req.URL.Path == "/kapis/iam.kubesphere.io/v1alpha2/login" {
		if adInject(req, wr) {
			return
		}
	}

	resp, err = client.Do(req)
	r.Body.Close()

	// combined for GET/POST
	if err != nil {
		http.Error(wr, err.Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range resp.Header {
		wr.Header().Set(k, v[0])
	}
	wr.WriteHeader(resp.StatusCode)
	io.Copy(wr, resp.Body)
	resp.Body.Close()

	PrintHTTP(req, resp)
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type LoginResponse struct {
	Message string `json:"message"`
}

func adInject(request *http.Request, resp http.ResponseWriter) bool {
	requestBody, err := ioutil.ReadAll(request.Body)
	var loginRequest LoginRequest
	err = json.Unmarshal(requestBody, &loginRequest)

	if err != nil {
		return false
	}

	srcConn := src.Ldap()
	defer srcConn.Close()
	dstConn := dst.Ldap()
	defer dstConn.Close()
	userSearchRequest := ldap.NewSearchRequest(
		viper.GetString("src.userSearchBase"),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(&(objectClass=person)(%s=%s))", viper.GetString("src.usernameAttribute"), loginRequest.Username),
		[]string{viper.GetString("src.usernameAttribute"), viper.GetString("src.mailAttribute"), viper.GetString("src.descriptionAttribute")},
		nil,
	)
	result, err := srcConn.Search(userSearchRequest)

	// 用源账户登录
	if err == nil && len(result.Entries) > 0 {
		user := result.Entries[0]
		err := srcConn.Bind(result.Entries[0].DN, loginRequest.Password)

		// 密码错误
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			resp.Header().Add("Content-Type", "application/json")
			resp.WriteHeader(http.StatusUnauthorized)
			data, _ := json.Marshal(LoginResponse{Message: "incorrect username or password"})
			resp.Write(data)
			return true
		} else if err != nil {
			resp.Header().Add("Content-Type", "application/json")
			resp.WriteHeader(http.StatusInternalServerError)
			data, _ := json.Marshal(LoginResponse{Message: err.Error()})
			resp.Write(data)
			return true
		}

		dstUserSearchRequest := ldap.NewSearchRequest(
			viper.GetString("dst.userSearchBase"),
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
			fmt.Sprintf("(&(objectClass=inetOrgPerson)(uid=%s))", loginRequest.Username),
			[]string{"sn"},
			nil,
		)

		dstResult, err := dstConn.Search(dstUserSearchRequest)

		// create if not exist
		if (dstResult != nil && len(dstResult.Entries) == 0) || ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {

			maxUid, err := getMaxUid(dstConn)

			if err != nil {
				resp.Header().Add("Content-Type", "application/json")
				resp.WriteHeader(http.StatusInternalServerError)
				data, _ := json.Marshal(LoginResponse{Message: err.Error()})
				resp.Write(data)
				return true
			}

			maxUid += 1

			pwd := uuid.New().String()
			userCreateRequest := ldap.NewAddRequest(fmt.Sprintf("uid=%s,%s", user.GetAttributeValue(viper.GetString("src.usernameAttribute")), viper.GetString("dst.userSearchBase")), nil)
			userCreateRequest.Attribute("objectClass", []string{"inetOrgPerson", "posixAccount", "top"})
			userCreateRequest.Attribute("cn", []string{user.GetAttributeValue("uid")})                    // RFC4519: common name(s) for which the entity is known by
			userCreateRequest.Attribute("sn", []string{pwd})                                              // RFC2256: last (family) name(s) for which the entity is known by
			userCreateRequest.Attribute("gidNumber", []string{"500"})                                     // RFC2307: An integer uniquely identifying a group in an administrative domain
			userCreateRequest.Attribute("homeDirectory", []string{viper.GetString("src.userSearchBase")}) // The absolute path to the home directory
			userCreateRequest.Attribute("uid", []string{user.GetAttributeValue("uid")})                   // RFC4519: user identifier
			userCreateRequest.Attribute("uidNumber", []string{strconv.Itoa(maxUid)})                      // RFC2307: An integer uniquely identifying a user in an administrative domain
			userCreateRequest.Attribute("mail", []string{viper.GetString("src.mailAttribute")})           // RFC1274: RFC822 Mailbox
			userCreateRequest.Attribute("userPassword", []string{pwd})                                    // RFC4519/2307: password of user
			userCreateRequest.Attribute("preferredLanguage", []string{"zh"})
			description := user.GetAttributeValue(viper.GetString("src.descriptionAttribute"))
			if description != "" {
				userCreateRequest.Attribute("description", []string{description}) // RFC4519: descriptive information
			}

			err = dstConn.Add(userCreateRequest)
			if err != nil {
				resp.Header().Add("Content-Type", "application/json")
				resp.WriteHeader(http.StatusUnauthorized)
				data, _ := json.Marshal(LoginResponse{Message: err.Error()})
				resp.Write(data)
				return true
			}
			log.Infof("user %s sync success", user.GetAttributeValue(viper.GetString("src.usernameAttribute")))
			loginRequest.Password = pwd
		} else {
			if err != nil {
				resp.Header().Add("Content-Type", "application/json")
				resp.WriteHeader(http.StatusUnauthorized)
				data, _ := json.Marshal(LoginResponse{Message: err.Error()})
				resp.Write(data)
				return true
			}
			loginRequest.Password = dstResult.Entries[0].GetAttributeValue("sn")
		}

	}

	data, _ := json.Marshal(loginRequest)
	request.Body = ioutil.NopCloser(bytes.NewReader(data))
	return false
}

var (
	src *pool.LdapClient
	dst *pool.LdapClient
)

func main() {
	flag.Parse()
	viper.SetConfigName("sync")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/kubesphere")
	viper.SetConfigType("yaml")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Fatalln("configuration file not found")
		} else {
			log.Fatalf("error parsing configuration file %s", err)
		}
	}

	stopChan := signals.SetupSignalHandler()

	viper.Debug()


	var err error

	src, err = pool.NewLdapClient(&pool.LdapOptions{
		Host:            viper.GetString("src.host"),
		ManagerDN:       viper.GetString("src.managerDN"),
		ManagerPassword: viper.GetString("src.managerPWD"),
	}, stopChan)

	if err != nil {
		log.Fatalln(err)
	}

	dst, err = pool.NewLdapClient(&pool.LdapOptions{
		Host:            viper.GetString("dst.host"),
		ManagerDN:       viper.GetString("dst.managerDN"),
		ManagerPassword: viper.GetString("dst.managerPWD"),
	}, stopChan)

	if err != nil {
		log.Fatalln(err)
	}

	//go HandleHTTP()
	proxy := NewProxy()

	log.Info("proxy to http://127.0.0.1:9090")
	if err := http.ListenAndServe(":19090", proxy); err != nil {
		log.Fatalln(err)
	}
}
func PrintHTTP(request *http.Request, response *http.Response) {
	log.V(4).Infof("%v %v\n", request.Method, request.RequestURI)
	for k, v := range request.Header {
		log.V(6).Info(k, ":", v)
	}
	log.V(6).Info("==============================")
	log.V(6).Infof("HTTP/1.1 %v\n", response.Status)
	for k, v := range response.Header {
		log.V(6).Info(k, ":", v)
	}
	log.V(6).Info("==============================")
}


func convertDNToMail(username, dn string) string {
	groups := strings.Split(dn, ",")
	domain := username + "@"
	for _, g := range groups {
		g2 := strings.Split(g, "=")
		if strings.EqualFold(g2[0], "dc") {
			domain += g2[1]
			domain += "."
		}
	}
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

func getMaxUid(conn ldap.Client) (int, error) {
	userSearchRequest := ldap.NewSearchRequest(viper.GetString("dst.userSearchBase"),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=inetOrgPerson))",
		[]string{"uidNumber"},
		nil)

	result, err := conn.Search(userSearchRequest)

	if err != nil {
		return 0, err
	}

	var maxUid int

	if len(result.Entries) == 0 {
		maxUid = 1000
	} else {
		for _, usr := range result.Entries {
			uid, _ := strconv.Atoi(usr.GetAttributeValue("uidNumber"))
			if uid > maxUid {
				maxUid = uid
			}
		}
	}

	return maxUid, nil
}

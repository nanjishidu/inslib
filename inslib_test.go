// inslib_test.go
package inslib

import (
	"fmt"
	"testing"
)

var (
	tcpProxy   = "127.0.01:1086"
	proxyProxy = "127.0.01:1087"
	dir        = "./uploadir"
)

func TestGetDataByName(t *testing.T) {
	SetTcpProxy(tcpProxy)
	var name = "hre926"
	nodes, err := GetDataByName(name)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(len(nodes[name]))
	var i = 0
	for _, v := range nodes {
		for _, vv := range v {
			filename, b := Download(vv, dir, false, name)
			if b {
				fmt.Println(filename)
				i++
			}
		}
	}
	fmt.Println(i)
	t.Log(nodes)
}

func TestGetDataByUrl(t *testing.T) {
	SetTcpProxy(tcpProxy)
	nodes, err := GetDataByUrl("https://www.instagram.com/p/BSuJJrGDeZp/")
	if err != nil {
		fmt.Println(err)
		t.Fatal(err)
	}
	for _, v := range nodes {
		filename, b := Download(v, dir, true)
		if b {
			fmt.Println(filename)
		}

	}
	t.Log(nodes)
}

func TestGetUsers(t *testing.T) {
	SetTcpProxy(tcpProxy)
	var q = "h"
	nodes, err := GetUsers(q)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range nodes {
		fmt.Println(v.User)

	}
	t.Log(nodes)
}

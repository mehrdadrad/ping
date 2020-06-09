# ping
[![Go Report Card](https://goreportcard.com/badge/github.com/mehrdadrad/ping)](https://goreportcard.com/report/github.com/mehrdadrad/ping)
[![GoDoc](https://godoc.org/github.com/mehrdadrad/ping?status.svg)](https://godoc.org/github.com/mehrdadrad/ping)

Golang native ICMP-based ping IPv4 and IPv6 library

## Features
- IPv4 and IPv6
- non-privileged datagram-oriented ICMP
- privileged raw ICMP
- type of server
- time to live
- source ip address
- incoming interface

## Supported platform
- Linux
- macOS

## Usage & Example

For usage and examples see the [Godoc](http://godoc.org/github.com/mehrdadrad/ping).

```go
package main

import (
	"fmt"
	"log"

	"github.com/mehrdadrad/ping"
)

func main() {
	p, err := ping.New("google.com")
	if err != nil {
		log.Fatal(err)
	}
  
  p.SetCount(4)
  
  r, err := p.Run()
	if err != nil {
		log.Fatal(err)
	}
  
  for pr := range r {
    fmt.Printf("%#v\n", pr)
  }
```
```
#go run main.go
ping.Response{RTT:4.938, Size:64, TTL:56, Seq:0, Addr:"172.217.5.206", If:"eth0", Err:error(nil)}
ping.Response{RTT:5.202, Size:64, TTL:56, Seq:1, Addr:"172.217.5.206", If:"eth0", Err:error(nil)}
ping.Response{RTT:6.576, Size:64, TTL:56, Seq:2, Addr:"172.217.5.206", If:"eth0", Err:error(nil)}
ping.Response{RTT:4.126, Size:64, TTL:56, Seq:3, Addr:"172.217.5.206", If:"eth0", Err:error(nil)}
ping.Response{RTT:4.983, Size:64, TTL:56, Seq:4, Addr:"172.217.5.206", If:"eth0", Err:error(nil)}

```

## License
This project is licensed under MIT license. Please read the LICENSE file.

## Contribute
Welcomes any kind of contribution, please follow the next steps:

- Fork the project on github.com.
- Create a new branch.
- Commit changes to the new branch.
- Send a pull request.

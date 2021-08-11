# PrivateBin CLI

A CLI for PrivateBin allowing easy pasting from the Terminal.

## Build & Install

```shell script
go build && install -m 755 ./privatebin /usr/local/bin/privatebin
```

## Usage

Currently, `privatebin` only support piping inputs on the Command Line.


```shell script
# Using Echo
echo test | privatebin

# Using Tail
tail -n 20 <FILE> | privatebin

# Using Cat
cat <FILE> | privatebin
```

## Using another server 

This fork, moreover support to set another privatebin server to use.

```shell
echo "hello world" | privatebin -s https://my-privatebin.private.server
```


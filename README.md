## Description

pScan - short for Port Scanner - executes TCP port scan
on a list of hosts.
pScan allows you to add, list, and delete hosts from the list.
pScan executes a port scan on specified TCP ports. You can customize the
target ports using a command line flag.
The utility also supports autocompletion.

Full documentation is also available [here](docs/pScan.md).

## Usage
To build the app, run the following command in the root folder:

```
$ go build .
```
Above command will generate `pScan` file. This name is defined in the `go.mod` file, and it will be the initialized module name.

After that you can run the program using the cmd.\
Example of adding a new host to list:

```
$ ./pScan.exe hosts add 168.168.0.192"
```

### Options

```
      --config string       config file (default is $HOME/.pScan.yaml)
  -h, --help                help for pScan
  -f, --hosts-file string   pScan hosts file (default "pScan.hosts")
```


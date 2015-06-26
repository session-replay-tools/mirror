## A tool to mirror packets to a target server

##Quick start
* [Download the latest mirror release](https://github.com/session-replay-tools/mirror/releases).
* Clone the repo: `git clone git://github.com/session-replay-tools/mirror.git`.

##Getting mirror installed 
1. cd mirror
2. ./configure 
  - choose appropriate configure options if needed
3. make
4. make install

###Configure Options for mirror
     --with-pfring=PATH  set path to PF_RING library sources
     --with-debug        compile mirror with debug support (saved in a log file)

##Running 
    ./mirror -s sourceMacAddress -t targetMacAddress -F <filter> -o <device> -i <device> -x destIPAddress -d 

    see -h for more details

##Note
1. Root privilege or the CAP_NET_RAW capability(e.g. setcap CAP_NET_RAW=ep mirror) is required 
##Release History
+ 2014.09  v1.0    mirror released


##Bugs and feature requests
Have a bug or a feature request? [Please open a new issue](https://github.com/session-replay-tools/mirror/issues). Before opening any issue, please search for existing issues.


## Copyright and license

Copyright 2014 under [the BSD license](LICENSE).

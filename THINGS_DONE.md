
#### MySQL Server
+ net start MySQL80
+ net stop MySQL80

#### added keyring for
+ keyring took awhile
+ What finally got it: https://stackoverflow.com/questions/44972186/install-mysql-keyring-plugin

#### DISCARD and IMPORT
+ looked into using, but also doesn't follow the Access requirements.


#### THe steps
+ off
+ remove es folder with main.ibd
+ start
+ reset data
+ print data  # mainly used to compare plain text of 'file' implementation
+ stop
+ flip {num_bits} {bits_offset}
+ start  # check error. if successfull they we can see the error 
    + TODO: if successful, see the data changed.
+ print data  # mainly used to compare plain text of 'file' implementation

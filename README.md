
# Stupid-RAT

This is the outcome of some stuff that i have learned while doing the ElearnSecurity PTX course


## Loader.cs

    Given code execution on the target machine, the loader.cs will download and reflectively execute the Persist.cs and the injector.cs
    and exit when it finishes.
## Persist.cs 

    if it is not already persisted. this will create a shortcut in the startup folder to execute the loader
    
## Injector.cs
    
    the injector will download the encrypted client.cs and inject it to (onedrive) process
  
## client.cs

    this the final piece that will be executed in (onedrive) process and connects back to the server.py


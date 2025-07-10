> Forked from the repository of a wannabe Microsoft MVP -> [@shiroinekotfs](https://github.com/shiroinekotfs)

# Windows Admin Center on Domain Controller

![image](https://github.com/shiroinekotfs/WAC-on-DC/assets/115929530/39b27ad8-bf3b-4691-9603-4934de2d4268)

## Getting started

You, first, install Windows Admin Center (Preview). If you don't have, [download it here](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewserver)

Once downloaded and installed (please ignore all warnings and errors), move your Powershell current directory into this repo folder, and try this command:

```powershell
powershell -ExecutionPolicy Bypass -File .\Fix-WAC-on-DC-InstallScript.ps1
```
> **⚠️ Note:** Make sure to run the script as a user with permissions to create groups in Active Directory.

Once it is done, you can try WAC on DC!

## Fork updates
- Fixes the creation of the Windows Admin Center CredSSP group.
- Automatically creates the group in Active Directory.
- Adds the current user to the newly created group.
- Adds a helper script to automate the WAC patch process using the provided functions.

## License

This project is based on [WAC-on-DC](https://github.com/shiroinekotfs/WAC-on-DC), licensed under the MIT License.
Modifications and additions by [SpyKeeR](https://github.com/SpyKeeR).

See the [LICENSE](./LICENSE) file for more details.

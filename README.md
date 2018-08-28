# winerva


**Helping to bring the management of stand-alone MS Windows machines under your control!**


## TOC

* [Overview](#overview)
    * [What is this?](#what-is-this)
    * [Why Ansible?](#why-ansible)
    * [Which operating systems?](#which-operating-systems)
    * [What does it do?](#what-does-it-do)
    * [Why the local Administrator account?](#why-the-local-administrator-account)
    * [How do I use it?](#how-do-i-use-it)
* [Configuration](#configuration)


## Overview

### What is this?

This project contains a PowerShell script that prepares a Windows machine to be remotely managed by Ansible, along with a batch file that allows for "one click" operation.


### Why Ansible?

[Ansible](https://www.ansible.com/overview/it-automation) is an open-source computer program that enables remote configuration and application deployment to target machines, without requiring the installation and maintenance of remote agent software. Desired state is written using [YAML](https://en.wikipedia.org/wiki/YAML) and [Jinja2](http://jinja.pocoo.org), which are converted into their matching PowerShell commands and executed remotely via WinRM.

Ansible's combination of free-to-use, agentless architecture, along with a data format that is both easy to read and write, make this an ideal system for low-cost IT maintenance. And, because Ansible communicates with Windows machines via WinRM, it is perfect for environments that contain a number of networked PCs running Windows, but do not have a domain controller.


### Which operating systems?

The list of currently supported operating systems are:

* MS Windows 10 (as of v1.0.0)
* MS Windows 8.1 (as of v1.1.0)
* MS Windows 7 SP1 (as of v.1.2.0)


### What does it do?

The script carries out the following tasks:

* Ensures [Chocolatey](https://chocolatey.org) is installed.
* Upgrades .NET to version 4.5 (latest available patch).
* Upgrades PowerShell to the latest available version.
* Ensures that [Carbon](http://get-carbon.org) for PowerShell is installed.
* Ensures the specified user account is present.
* Ensures that that user account is a member of the local `Administrators` group.
* Adds (if missing) the computer's name to an inventory file, which can later be used by Ansible.


### Why the local Administrator account?

Ansible will use this account when connecting to each target machine. Administrator-level access is required for a lot of configuration actions and application deployments, so it just makes sense. That being said, the credentials should be kept in a safe place (meaning, **not** copied to the target machine), and the password should be [lengthy](https://stormpath.com/blog/5-myths-password-security).


### How do I use it?

1. Download the contents of the `src/` folder to removable media (such as a USB flash drive).
2. Ensure that the contents of the configuration file are correct for the target machine. _You'll need to change the credentials_; if you like, you can use an existing account. The script will automatically add it to the local Administrators group, if it isn't there already.
3. Attach the removable media, and execute `run.cmd`.

**This is script is safe to run more than once on the same machine.**


## Configuration

The following configuration options are stored in the file `config.psd1`, which is in the same location as `run.cmd`. This file is a [PowerShell data file](http://www.dexterposh.com/2017/06/powershell-psd1-files-for-env-config-data.html), comprised of a single hash table. The syntax and grammar are the same as that for PowerShell script files.


### Local administrator account

The credentials for the local administrator account are kept in the file `config.psd1` under the entry `LocalAdmin`. Note that the password must be entered as a plain text value. Refer to the comments within the configuration file for further instructions.


## License

MIT (please refer to the file named LICENSE).

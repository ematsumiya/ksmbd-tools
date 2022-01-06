# ksmbd-tools

### Building

##### Install prerequisite packages:

- For Ubuntu:
  - `sudo apt-get install autoconf libtool pkg-config libnl-3-dev libnl-genl-3-dev libglib2.0-dev libkrb5-dev`

- For Fedora, RHEL:
  - `sudo yum install autoconf automake libtool glib2-devel libnl3-devel krb5-devel`

- For CentOS:
  - `sudo yum install glib2-devel libnl3-devel krb5-devel`

- For openSUSE:
  - `sudo zypper install glib2-devel libnl3-devel krb5-devel`


##### Building:

- clone this repository
- `cd ksmbd-tools`
- `./autogen.sh`
- `./configure`
- `make`
- `make install`


### Usage

All administration tasks must be done as root.

##### Setup:

- Install ksmbd kernel driver (requires CONFIG_SMB_SERVER=y)
	- `modprobe ksmbd`
- Create user/password for SMB share
	- `mkdir /etc/ksmbd`
	- `ksmbdctl user add <username>`
	- Enter password for user when prompted
- Create `/etc/ksmbd/smb.conf` file
	- Refer `smb.conf.example`
- Add share to `smb.conf`
	- This can be done either manually or with `ksmbdctl`, e.g.:
	- `ksmbdctl share add myshare -o "guest ok = yes, writable = yes, path = /mnt/data"`

	- Note: share options (-o) must always be enclosed with double quotes ("...").
- Start ksmbd user space daemon
	- `ksmbdctl daemon start`
- Access share from Windows or Linux


##### Stopping and restarting the daemon:

First, kill user and kernel space daemon:
  - `ksmbdctl daemon shutdown`

Then, to restart the daemon, run:
  - `ksmbdctl daemon start`

Or to shut it down completely:
  - `rmmod ksmbd`


### Debugging

- Enable debugging all components
  - `ksmbdctl daemon debug "all"`
- Enable debugging a single component (see more below)
  - `ksmbdctl daemon debug "smb"`
- Run the commands above with the same component name again to disable it

Currently available debug components:
smb, auth, vfs, oplock, ipc, conn, rdma


### User management

- ksmbdctl user
  - Adds, updates, deletes, or lists users from database.
  - Default database file is `/etc/ksmbd/users.db`, but can be changed with '-d'
    option.

- ksmbdctl share
  - Adds, updates, deletes, or lists net shares from config file.
  - Default config file is `/etc/ksmbd/smb.conf`, but can be changed with '-c'
    option.

`ksmbdctl share add` does not modify `[global]` section in config file; only net
share configs are supported at the moment.

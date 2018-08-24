# Changelog for winerva

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).


## [1.1.0] - 2018-08-24

### Added
* Support for MS Windows 8.1
* Script now installs latest available version of PowerShell.

### Fixed
* When updating `hostnames`, a new line is added between names.
* When updating `hostnames`, empty lines are removed.
* When an exception is thrown, the `Catch` block actually now displays the error information.


## [1.0.0] - 2018-08-23

First release.

### Added
* Support for MS Windows 10.

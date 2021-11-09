# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to the following versioning pattern:

Given a version number MAJOR.MINOR.PATCH, increment:

- MAJOR version when **breaking changes** are introduced;
- MINOR version when **backwards compatible changes** are introduced;
- PATCH version when backwards compatible bug **fixes** are implemented.


## [Unreleased]
### Fixed
- point at infinity verification in signature and public key

## [1.3.2] - 2021-11-04
### Fixed
- Signature r and s range check

## [1.3.1] - 2021-04-06
### Fixed
- swapped hex names (hex129, hex160, hex128) in der utils

## [1.3.0] - 2021-01-26
### Added
- assembly signing configs

## [1.2.1] - 2020-09-27
### Fixed
- short circuit logic

## [1.2.0] - 2020-06-23
### Added 
- support for netstandard1.3, net40, and net452

## [1.1.0] - 2020-05-12
### Added
- .NET Standard 2.0 compatibility

## [1.0.0] - 2020-04-14
### Added
- first official version
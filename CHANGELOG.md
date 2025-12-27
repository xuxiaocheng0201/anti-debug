# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2025-12-27

### Added

* 实现 `windows`/`linux`/`android`/`macos` 平台的 `deny_attach`

## [0.2.0] - 2025-10-22

### Added

* 实现 `android` 平台的 `is_debugger_present` (与 linux 一致)
* 添加 `windows` 独有的 `deep-dectet` feature

### Changed

* 优化 `linux`/`macos` 平台检测逻辑
* 优化 `is_debugger_present` API

## [0.1.1] - 2025-7-31

### Changed

* 改正描述

## [0.1.0] - 2025-7-31 (yanked)

### Added

* 实现 `windows`/`linux`/`macos` 平台的 `is_debugger_present`

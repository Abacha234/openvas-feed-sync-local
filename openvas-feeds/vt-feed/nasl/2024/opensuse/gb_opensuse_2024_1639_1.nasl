# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856161");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-28858", "CVE-2023-28859");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-05 19:06:46 +0000 (Wed, 05 Apr 2023)");
  script_tag(name:"creation_date", value:"2024-05-24 01:10:40 +0000 (Fri, 24 May 2024)");
  script_name("openSUSE: Security Advisory for python (SUSE-SU-2024:1639-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1639-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/N46ZXKJ6VUVQGRTQOYL2TXPANED6ECDD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the SUSE-SU-2024:1639-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-argcomplete, python-Fabric, python-PyGithub, python-
  antlr4-python3-runtime, python-avro, python-chardet, python-distro, python-
  docker, python-fakeredis, python-fixedint, python-httplib2, python-httpretty,
  python-javaproperties, python-jsondiff, python-knack, python-marshmallow,
  python-opencensus, python-opencensus-context, python-opencensus-ext-threading,
  python-opentelemetry-api, python-opentelemetry-sdk, python-opentelemetry-
  semantic-conventions, python-opentelemetry-test-utils, python-pycomposefile,
  python-pydash, python-redis, python-retrying, python-semver, python-sshtunnel,
  python-strictyaml, python-sure, python-vcrpy, python-xmltodict contains the
  following fixes:

  Changes in python-argcomplete \- Update to 3.3.0 (bsc#1222880): * Preserve
  compatibility with argparse option tuples of length 4. This update is required
  to use argcomplete on Python 3.11.9+ or 3.12.3+. \- update to 3.2.3: * Allow
  register-python-argcomplete output to be used as lazy-loaded zsh completion
  module (#475) \- Move debug_stream initialization to helper method to allow fd 9
  behavior to be overridden in subclasses (#471)

  * update to 3.2.2:

  * Expand tilde in zsh

  * Remove coverage check

  * Fix zsh test failures: avoid coloring terminal

  * update to 3.2.1:

  * Allow explicit zsh global completion activation (#467)

  * Fix and test global completion in zsh (#463, #466)

  * Add yes option to activate-global-python-argcomplete (#461)

  * Test suite improvements

  * drop without_zsh.patch: obsolete

  * update to 3.1.6:

  * Respect user choice in activate-global-python-argcomplete

  * Escape colon in zsh completions. Fixes #456

  * Call _default as a fallback in zsh global completion

  * update to 3.1.4:

  * Call _default as a fallback in zsh global completion

  * zsh: Allow to use external script (#453)

  * Add support for Python 3.12 and drop EOL 3.6 and 3.7 (#449)

  * Use homebrew prefix by default

  * zsh: Allow to use external script (#453)

  Changes in python-Fabric: \- Update to 3.2.2 \- add fix-test-deps.patch to
  remove vendored dependencies *[Bug]: fabric.runners.Remote failed to properly
  deregister its SIGWINCH signal handler on shutdown  in rare situations this
  could cause tracebacks when the Python process receives SIGWINCH while no remote
  session is active. This has been fixed. * [Bug] #2204: The signal handling
  functionality added in Fabric 2.6 caused unrecoverable tracebacks when invoked
  from inside a thread (such as the use of fabric ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'python' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

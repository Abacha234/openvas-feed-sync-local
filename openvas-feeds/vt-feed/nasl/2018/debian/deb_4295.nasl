# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704295");
  script_cve_id("CVE-2018-12361", "CVE-2018-12367", "CVE-2018-12371", "CVE-2018-5156", "CVE-2018-5187");
  script_tag(name:"creation_date", value:"2018-09-15 22:00:00 +0000 (Sat, 15 Sep 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-06 18:44:00 +0000 (Thu, 06 Dec 2018)");

  script_name("Debian: Security Advisory (DSA-4295)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4295");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4295");
  script_xref(name:"URL", value:"https://support.mozilla.org/en-US/kb/new-thunderbird-60");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/thunderbird");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'thunderbird' package(s) announced via the DSA-4295 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Thunderbird: Multiple memory safety errors and use-after-frees may lead to the execution of arbitrary code or denial of service.

Debian follows the Thunderbird upstream releases. Support for the 52.x series has ended, so starting with this update we're now following the 60.x releases.

Between 52.x and 60.x, Thunderbird has undergone significant internal updates, which makes it incompatible with a number of extensions. For more information please refer to [link moved to references]

In addition, the new Thunderbird packages require Rust to build. A compatible Rust toolchain has been backported to Debian stretch, but is not available for all architectures which previously supported the purely C++-based Thunderbird packages. Thus, the new Thunderbird packages don't support the mips, mips64el and mipsel architectures at this point.

For the stable distribution (stretch), these problems have been fixed in version 1:60.0-3~deb9u1.

We recommend that you upgrade your thunderbird packages.

For the detailed security status of thunderbird please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
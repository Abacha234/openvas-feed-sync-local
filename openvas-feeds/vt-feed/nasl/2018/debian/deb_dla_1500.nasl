# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891500");
  script_cve_id("CVE-2015-5352", "CVE-2015-5600", "CVE-2015-6563", "CVE-2015-6564", "CVE-2016-10009", "CVE-2016-10011", "CVE-2016-10012", "CVE-2016-10708", "CVE-2016-1908", "CVE-2016-3115", "CVE-2016-6515", "CVE-2017-15906");
  script_tag(name:"creation_date", value:"2018-09-09 22:00:00 +0000 (Sun, 09 Sep 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-18 13:51:00 +0000 (Thu, 18 Aug 2022)");

  script_name("Debian: Security Advisory (DLA-1500)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1500");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1500-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssh' package(s) announced via the DLA-1500 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The security update of OpenSSH announced as DLA 1500-1 introduced a bug in openssh-client: when X11 forwarding is enabled (via system-wide configuration in ssh_config or via -X command line switch), but no DISPLAY is set, the client produces a 'DISPLAY '(null)' invalid, disabling X11 forwarding' warning. These bug was introduced by the patch set to fix the CVE-2016-1908 issue. For reference, the following is the relevant section of the original announcement:

CVE-2016-1908

OpenSSH mishandled untrusted X11 forwarding when the X server disables the SECURITY extension. Untrusted connections could obtain trusted X11 forwarding privileges. Reported by Thomas Hoger.

For Debian 8 Jessie, this problem has been fixed in version 1:6.7p1-5+deb8u7.

We recommend that you upgrade your openssh packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'openssh' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
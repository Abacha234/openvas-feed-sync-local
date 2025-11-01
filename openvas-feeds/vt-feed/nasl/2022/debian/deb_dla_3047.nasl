# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893047");
  script_cve_id("CVE-2021-26720", "CVE-2021-3468");
  script_tag(name:"creation_date", value:"2022-06-08 01:00:10 +0000 (Wed, 08 Jun 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-25 21:27:00 +0000 (Thu, 25 Feb 2021)");

  script_name("Debian: Security Advisory (DLA-3047)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3047");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3047");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/avahi");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'avahi' package(s) announced via the DLA-3047 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Debian package of Avahi, a framework for Multicast DNS Service Discovery, executed the script avahi-daemon-check-dns.sh with root privileges which would allow a local attacker to cause a denial of service or create arbitrary empty files via a symlink attack on files under /var/run/avahi-daemon. This script is now executed with the privileges of user and group avahi and requires sudo in order to achieve that.

The aforementioned script has been removed from Debian 10 Buster onwards. The workaround could not be implemented for Debian 9 Stretch because libnss-mdns 0.10 does not provide the required functionality to replace it.

Furthermore it was found (CVE-2021-3468) that the event used to signal the termination of the client connection on the avahi Unix socket is not correctly handled in the client_work function, allowing a local attacker to trigger an infinite loop.

For Debian 9 stretch, these problems have been fixed in version 0.6.32-2+deb9u1.

We recommend that you upgrade your avahi packages.

For the detailed security status of avahi please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'avahi' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
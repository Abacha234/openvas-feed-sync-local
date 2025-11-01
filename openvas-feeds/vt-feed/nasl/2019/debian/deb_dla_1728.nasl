# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891728");
  script_cve_id("CVE-2018-20685", "CVE-2019-6109", "CVE-2019-6111");
  script_tag(name:"creation_date", value:"2019-03-25 22:00:00 +0000 (Mon, 25 Mar 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-23 23:16:00 +0000 (Thu, 23 Feb 2023)");

  script_name("Debian: Security Advisory (DLA-1728)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1728");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1728");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssh' package(s) announced via the DLA-1728 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple scp client vulnerabilities have been discovered in OpenSSH, the premier connectivity tool for secure remote shell login and secure file transfer.

CVE-2018-20685

In scp.c, the scp client allowed remote SSH servers to bypass intended access restrictions via the filename of . or an empty filename. The impact was modifying the permissions of the target directory on the client side.

CVE-2019-6109

Due to missing character encoding in the progress display, a malicious server (or Man-in-The-Middle attacker) was able to employ crafted object names to manipulate the client output, e.g., by using ANSI control codes to hide additional files being transferred. This affected refresh_progress_meter() in progressmeter.c.

CVE-2019-6111

Due to the scp implementation being derived from 1983 rcp, the server chooses which files/directories are sent to the client. However, the scp client only performed cursory validation of the object name returned (only directory traversal attacks are prevented). A malicious scp server (or Man-in-The-Middle attacker) was able to overwrite arbitrary files in the scp client target directory. If recursive operation (-r) was performed, the server was able to manipulate subdirectories, as well (for example, to overwrite the .ssh/authorized_keys file).

For Debian 8 Jessie, these problems have been fixed in version 1:6.7p1-5+deb8u8.

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
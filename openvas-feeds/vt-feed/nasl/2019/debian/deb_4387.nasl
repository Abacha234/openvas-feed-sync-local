# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704387");
  script_cve_id("CVE-2018-20685", "CVE-2019-6109", "CVE-2019-6111");
  script_tag(name:"creation_date", value:"2019-02-08 23:00:00 +0000 (Fri, 08 Feb 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-23 23:16:00 +0000 (Thu, 23 Feb 2023)");

  script_name("Debian: Security Advisory (DSA-4387)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4387");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4387");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openssh");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssh' package(s) announced via the DSA-4387 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Harry Sintonen from F-Secure Corporation discovered multiple vulnerabilities in OpenSSH, an implementation of the SSH protocol suite. All the vulnerabilities are in found in the scp client implementing the SCP protocol.

CVE-2018-20685

Due to improper directory name validation, the scp client allows servers to modify permissions of the target directory by using empty or dot directory name.

CVE-2019-6109

Due to missing character encoding in the progress display, the object name can be used to manipulate the client output, for example to employ ANSI codes to hide additional files being transferred.

CVE-2019-6111

Due to scp client insufficient input validation in path names sent by server, a malicious server can do arbitrary file overwrites in target directory. If the recursive (-r) option is provided, the server can also manipulate subdirectories as well.

The check added in this version can lead to regression if the client and the server have differences in wildcard expansion rules. If the server is trusted for that purpose, the check can be disabled with a new -T option to the scp client.

For the stable distribution (stretch), these problems have been fixed in version 1:7.4p1-10+deb9u5.

We recommend that you upgrade your openssh packages.

For the detailed security status of openssh please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openssh' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
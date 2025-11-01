# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703182");
  script_cve_id("CVE-2015-1782");
  script_tag(name:"creation_date", value:"2015-03-10 23:00:00 +0000 (Tue, 10 Mar 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3182)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3182");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3182");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libssh2' package(s) announced via the DSA-3182 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mariusz Ziulek reported that libssh2, a SSH2 client-side library, was reading and using the SSH_MSG_KEXINIT packet without doing sufficient range checks when negotiating a new SSH session with a remote server. A malicious attacker could man in the middle a real server and cause a client using the libssh2 library to crash (denial of service) or otherwise read and use unintended memory areas in this process.

For the stable distribution (wheezy), this problem has been fixed in version 1.4.2-1.1+deb7u1.

We recommend that you upgrade your libssh2 packages.");

  script_tag(name:"affected", value:"'libssh2' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
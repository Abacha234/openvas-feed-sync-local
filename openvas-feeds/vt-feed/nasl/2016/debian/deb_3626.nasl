# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703626");
  script_cve_id("CVE-2016-6210");
  script_tag(name:"creation_date", value:"2016-08-02 05:25:52 +0000 (Tue, 02 Aug 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-07 11:29:00 +0000 (Thu, 07 Feb 2019)");

  script_name("Debian: Security Advisory (DSA-3626)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3626");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3626");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssh' package(s) announced via the DSA-3626 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eddie Harari reported that the OpenSSH SSH daemon allows user enumeration through timing differences when trying to authenticate users. When sshd tries to authenticate a non-existing user, it will pick up a fixed fake password structure with a hash based on the Blowfish algorithm. If real users passwords are hashed using SHA256/SHA512, then a remote attacker can take advantage of this flaw by sending large passwords, receiving shorter response times from the server for non-existing users.

For the stable distribution (jessie), this problem has been fixed in version 1:6.7p1-5+deb8u3.

For the unstable distribution (sid), this problem has been fixed in version 1:7.2p2-6.

We recommend that you upgrade your openssh packages.");

  script_tag(name:"affected", value:"'openssh' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703487");
  script_cve_id("CVE-2016-0787");
  script_tag(name:"creation_date", value:"2016-03-08 07:07:47 +0000 (Tue, 08 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-3487)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3487");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3487");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libssh2' package(s) announced via the DSA-3487 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andreas Schneider reported that libssh2, a SSH2 client-side library, passes the number of bytes to a function that expects number of bits during the SSHv2 handshake when libssh2 is to get a suitable value for group order in the Diffie-Hellman negotiation. This weakens significantly the handshake security, potentially allowing an eavesdropper with enough resources to decrypt or intercept SSH sessions.

For the oldstable distribution (wheezy), this problem has been fixed in version 1.4.2-1.1+deb7u2.

For the stable distribution (jessie), this problem has been fixed in version 1.4.3-4.1+deb8u1.

We recommend that you upgrade your libssh2 packages.");

  script_tag(name:"affected", value:"'libssh2' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
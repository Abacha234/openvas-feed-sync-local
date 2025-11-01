# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702966");
  script_cve_id("CVE-2014-0178", "CVE-2014-0244", "CVE-2014-3493");
  script_tag(name:"creation_date", value:"2014-06-22 22:00:00 +0000 (Sun, 22 Jun 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2966)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2966");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2966");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DSA-2966 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered and fixed in Samba, a SMB/CIFS file, print, and login server:

CVE-2014-0178

Information leak vulnerability in the VFS code, allowing an authenticated user to retrieve eight bytes of uninitialized memory when shadow copy is enabled.

CVE-2014-0244

Denial of service (infinite CPU loop) in the nmbd Netbios name service daemon. A malformed packet can cause the nmbd server to enter an infinite loop, preventing it to process later requests to the Netbios name service.

CVE-2014-3493

Denial of service (daemon crash) in the smbd file server daemon. An authenticated user attempting to read a Unicode path using a non-Unicode request can force the daemon to overwrite memory at an invalid address.

For the stable distribution (wheezy), these problems have been fixed in version 2:3.6.6-6+deb7u4.

For the testing distribution (jessie), these problems have been fixed in version 2:4.1.9+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 2:4.1.9+dfsg-1.

We recommend that you upgrade your samba packages.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
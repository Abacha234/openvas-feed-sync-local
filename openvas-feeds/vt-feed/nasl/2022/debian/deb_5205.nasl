# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705205");
  script_cve_id("CVE-2022-2031", "CVE-2022-32742", "CVE-2022-32744", "CVE-2022-32745", "CVE-2022-32746");
  script_tag(name:"creation_date", value:"2022-08-13 01:00:16 +0000 (Sat, 13 Aug 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 18:09:00 +0000 (Mon, 29 Aug 2022)");

  script_name("Debian: Security Advisory (DSA-5205)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5205");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5205");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/samba");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DSA-5205 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Samba, a SMB/CIFS file, print, and login server for Unix.

CVE-2022-2031

Luke Howard reported that Samba AD users can bypass certain restrictions associated with changing passwords. A user who has been requested to change their password can exploit this to obtain and use tickets to other services.

CVE-2022-32742

Luca Moro reported that a SMB1 client with write access to a share can cause server memory content to be leaked.

CVE-2022-32744

Joseph Sutton reported that Samba AD users can forge password change requests for any user, resulting in privilege escalation.

CVE-2022-32745

Joseph Sutton reported that Samba AD users can crash the server process with a specially crafted LDAP add or modify request.

CVE-2022-32746

Joseph Sutton and Andrew Bartlett reported that Samba AD users can cause a use-after-free in the server process with a specially crafted LDAP add or modify request.

For the stable distribution (bullseye), these problems have been fixed in version 2:4.13.13+dfsg-1~deb11u5. The fix for CVE-2022-32745 required an update to ldb 2:2.2.3-2~deb11u2 to correct the defect.

We recommend that you upgrade your samba packages.

For the detailed security status of samba please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
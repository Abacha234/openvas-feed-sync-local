# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705015");
  script_cve_id("CVE-2020-25717");
  script_tag(name:"creation_date", value:"2021-12-01 02:00:06 +0000 (Wed, 01 Dec 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-25 17:26:00 +0000 (Fri, 25 Feb 2022)");

  script_name("Debian: Security Advisory (DSA-5015)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5015");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-5015");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2020-25717.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/samba");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DSA-5015 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andrew Bartlett discovered that Samba, a SMB/CIFS file, print, and login server for Unix, may map domain users to local users in an undesired way. This could allow a user in an AD domain to potentially become root on domain members.

A new parameter min domain uid (default 1000) has been added to specify the minimum uid allowed when mapping a local account to a domain account.

Further details and workarounds can be found in the upstream advisory [link moved to references]

For the oldstable distribution (buster), this problem has been fixed in version 2:4.9.5+dfsg-5+deb10u2. Additionally the update mitigates CVE-2020-25722. Unfortunately the changes required to fix additional CVEs affecting Samba as an AD-compatible domain controller are too invasive to be backported. Thus users using Samba as an AD-compatible domain controller are encouraged to migrate to Debian bullseye. From this point onwards AD domain controller setups are no longer supported in Debian oldstable.

We recommend that you upgrade your samba packages.

For the detailed security status of samba please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
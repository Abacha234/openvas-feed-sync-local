# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53522");
  script_cve_id("CVE-2005-0205");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-692)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-692");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-692");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kdenetwork' package(s) announced via the DSA-692 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The KDE team fixed a bug in kppp in 2002 which was now discovered to be exploitable by iDEFENSE. By opening a sufficiently large number of file descriptors before executing kppp which is installed setuid root a local attacker is able to take over privileged file descriptors.

For the stable distribution (woody) this problem has been fixed in version 2.2.2-14.7.

The testing (sarge) and unstable (sid) distributions are not affected since KDE 3.2 already contained the correction.

We recommend that you upgrade your kppp package.");

  script_tag(name:"affected", value:"'kdenetwork' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
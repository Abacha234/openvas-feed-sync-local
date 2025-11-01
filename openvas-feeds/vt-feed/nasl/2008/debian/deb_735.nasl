# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53982");
  script_cve_id("CVE-2005-1993");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-735)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-735");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-735");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sudo' package(s) announced via the DSA-735 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A local user who has been granted permission to run commands via sudo could run arbitrary commands as a privileged user due to a flaw in sudo's pathname validation. This bug only affects configurations which have restricted user configurations prior to an ALL directive in the configuration file. A workaround is to move any ALL directives to the beginning of the sudoers file, see the advisory at for more information.

For the old stable Debian distribution (woody), this problem has been fixed in version 1.6.6-1.3woody1.

For the current stable distribution (sarge), this problem has been fixed in version 1.6.8p7-1.1sarge1.

Note that packages are not yet ready for certain architectures, these will be released as they become available.

We recommend that you upgrade your sudo package.");

  script_tag(name:"affected", value:"'sudo' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
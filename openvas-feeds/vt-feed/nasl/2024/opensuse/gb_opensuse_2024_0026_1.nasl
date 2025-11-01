# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833595");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 12:56:07 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for seamonkey (openSUSE-SU-2024:0026-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0026-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OGI7EUNMLZU4UAVRG45B5WQC4TV4VFIL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey'
  package(s) announced via the openSUSE-SU-2024:0026-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for seamonkey fixes the following issues:

     Update to 2.53.18.1:

  * Update the NSS library to the latest esr 115 version for the final
       2.53.18.1 release.

  * SeaMonkey 2.53.18.1 uses the same backend as Firefox and contains the
       relevant Firefox 60.8 security fixes.

  * SeaMonkey 2.53.18.1 shares most parts of the mail and news code with
       Thunderbird. Please read the Thunderbird 60.8.0 release notes for
       specific security fixes in this release.

  * Additional important security fixes up to Current Firefox 115.7 and
       Thunderbird 115.7 ESR plus many enhancements have been backported. We
       will continue to enhance SeaMonkey security in subsequent 2.53.x beta
       and release versions as fast as we are able to.");

  script_tag(name:"affected", value:"'seamonkey' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

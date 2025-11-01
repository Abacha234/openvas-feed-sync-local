# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856754");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-47533");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-11-29 05:00:47 +0000 (Fri, 29 Nov 2024)");
  script_name("openSUSE: Security Advisory for cobbler (openSUSE-SU-2024:0382-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0382-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CGWWFM26ZMG5SCPMDNQQNYHHTROXVX2Q");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cobbler'
  package(s) announced via the openSUSE-SU-2024:0382-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cobbler fixes the following issues:

     Update to 3.3.7:

  * Security: Fix issue that allowed anyone to connect to the API as admin
         (CVE-2024-47533, boo#1231332)

  * bind - Fix bug that prevents cname entries from being generated
         successfully

  * Fix build on RHEL9 based distributions (fence-agents-all split)

  * Fix for Windows systems

  * Docs: Add missing dependencies for source installation

  * Fix issue that prevented systems from being synced when the profile
         was edited

     Update to 3.3.6:

  * Upstream all openSUSE specific patches that were maintained in Git

  * Fix rename of items that had uppercase letters

  * Skip inconsistent collections instead of crashing the daemon

  - Update to 3.3.5:

  * Added collection indices for UUID's, MAC's, IP addresses and
         hostnames boo#1219933

  * Re-added to_dict() caching

  * Added lazy loading for the daemon (off by default)

  - Update to 3.3.4:

  * Added cobbler-tests-containers subpackage

  * Updated the distro_signatures.json database

  * The default name for grub2-efi changed to grubx64.efi to match the
         DHCP template

  - Do generate boot menus even if no profiles or systems - only local boot

  - Avoid crashing running buildiso in certain conditions.

  - Fix settings migration schema to work while upgrading on existing
       running Uyuni and SUSE Manager servers running with old Cobbler settings
       (boo#1203478)

  - Consider case of 'next_server' being a hostname during migration
       of Cobbler collections.

  - Fix problem with 'proxy_url_ext' setting being None type.

  - Update v2 to v3 migration script to allow migration of collections that
       contains settings from Cobbler 2. (boo#1203478)

  - Fix problem for the migration of 'autoinstall' collection attribute.

  - Fix failing Cobbler tests after upgrading to 3.3.3.

  - Fix regression: allow empty string as interface_type value (boo#1203478)

  - Avoid possible override of existing values during migration
       of collections to 3.0.0 (boo#1206160)

  - Add missing code for previous patch file around boot_loaders migration.

  - Improve Cobbler performance with item cache and threadpool (boo#1205489)

  - Skip collections that are inconsistent instead of crashing (boo#1205749)

  - Items: Fix creation of 'default' NetworkInterface (boo#1206520)

  - S390X systems require their kernel options to have a linebreak at 79
       characters (boo#1207595)

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'cobbler' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

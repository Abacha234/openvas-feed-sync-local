# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856747");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-11-29 05:00:25 +0000 (Fri, 29 Nov 2024)");
  script_name("openSUSE: Security Advisory for seamonkey (openSUSE-SU-2024:0381-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0381-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZCBM65JXGQLO4VAA4PM3Q466RSC2IZRV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey'
  package(s) announced via the openSUSE-SU-2024:0381-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for seamonkey fixes the following issues:

     Update to SeaMonkey 2.53.19:

  * Cancel button in SeaMonkey bookmarking star ui not working bug 1872623.

  * Remove OfflineAppCacheHelper.jsm copy from SeaMonkey and use the
         one in toolkit bug 1896292.

  * Remove obsolete registerFactoryLocation calls from cZ bug 1870930.

  * Remove needless implements='nsIDOMEventListener' and QI bug 1611010.

  * Replace use of nsIStandardURL::Init bug 1864355.

  * Switch SeaMonkey website from hg.mozilla.org to heptapod. bug 1870934.

  * Allow view-image to open a data: URI by setting a flag on the loadinfo
         bug 1877001.

  * Save-link-as feature should use the loading principal and context menu
         using nsIContentPolicy.TYPE_SAVE_AS_DOWNLOAD bug 1879726.

  * Use punycode in SeaMonkey JS bug 1864287.

  * Font lists in preferences are no longer grouped by font type, port
         asynchronous handling like Bug 1399206 bug 1437393.

  * SeaMonkey broken tab after undo closed tab with invalid protocol bug
         1885748.

  * SeaMonkey session restore is missing the checkboxes in the Classic
         theme bug 1896174.

  * Implement about:credits on seamonkey-project.org website bug 1898467.

  * Fix for the 0.0.0.0 day vulnerability oligo summary.

  * Link in update notification does not open Browser bug 1888364.

  * Update ReadExtensionPrefs in Preferences.cpp bug 1890196.

  * Add about:seamonkey page to SeaMonkey bug 1897801.

  * SeaMonkey 2.53.19 uses the same backend as Firefox and contains the
         relevant Firefox 60.8 security fixes.

  * SeaMonkey 2.53.19 shares most parts of the mail and news code with
         Thunderbird. Please read the Thunderbird 60.8.0 release notes for
         specific security fixes in this release.

  * Additional important security fixes up to Current Firefox 115.14 and
         Thunderbird 115.14 ESR plus many enhancements have been backported. We
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

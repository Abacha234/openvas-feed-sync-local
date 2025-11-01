# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856385");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-21131", "CVE-2024-21138", "CVE-2024-21140", "CVE-2024-21144", "CVE-2024-21145", "CVE-2024-21147");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 23:15:16 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-08-28 04:00:27 +0000 (Wed, 28 Aug 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2024:2786-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2786-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/F4GPWWS6QXNVSLPPSK3MAZTPQ3GYNIWI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2024:2786-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openjdk fixes the following issues:

  Update to version jdk8u422 (icedtea-3.32.0):

  * Security fixes

  * JDK-8314794, CVE-2024-21131, bsc#1228046: Improve UTF8 String supports

  * JDK-8319859, CVE-2024-21138, bsc#1228047: Better symbol storage

  * JDK-8320097: Improve Image transformations

  * JDK-8320548, CVE-2024-21140, bsc#1228048: Improved loop handling

  * JDK-8322106, CVE-2024-21144, bsc#1228050: Enhance Pack 200 loading

  * JDK-8323231, CVE-2024-21147, bsc#1228052: Improve array management

  * JDK-8323390: Enhance mask blit functionality

  * JDK-8324559, CVE-2024-21145, bsc#1228051: Improve 2D image handling

  * JDK-8325600: Better symbol storage

  * Import of OpenJDK 8 u422 build 05

  * JDK-8025439: [TEST BUG] [macosx] PrintServiceLookup.lookupPrintServices
      doesn't work properly since jdk8b105

  * JDK-8069389: CompilerOracle prefix wildcarding is broken for long strings

  * JDK-8159454: [TEST_BUG] javax/swing/ToolTipManager/7123767/
      /bug7123767.java: number of checked graphics configurations should be
      limited

  * JDK-8198321: javax/swing/JEditorPane/5076514/bug5076514.java fails

  * JDK-8203691: [TESTBUG] Test /runtime/containers/cgroup/PlainRead.java fails

  * JDK-8205407: [windows, vs 2017] C4800 after 8203197

  * JDK-8235834: IBM-943 charset encoder needs updating

  * JDK-8239965: XMLEncoder/Test4625418.java fails due to 'Error: Cp943 - can't
      read properly'

  * JDK-8240756: [macos] SwingSet2:TableDemo:Printed Japanese characters were
      garbled

  * JDK-8256152: tests fail because of ambiguous method resolution

  * JDK-8258855: Two tests sun/security/krb5/auto/ /ReplayCacheTestProc.java and
      ReplayCacheTestProcWithMD5.java failed on OL8.3

  * JDK-8262017: C2: assert(n != __null) failed: Bad immediate dominator info.

  * JDK-8268916: Tests for AffirmTrust roots

  * JDK-8278067: Make HttpURLConnection default keep alive timeout configurable

  * JDK-8291226: Create Test Cases to cover scenarios for JDK-8278067

  * JDK-8291637: HttpClient default keep alive timeout not followed if server
      sends invalid value

  * JDK-8291638: Keep-Alive timeout of 0 should close connection immediately

  * JDK-8293562: KeepAliveCache Blocks Threads while Closing Connections

  * JDK-8303466: C2: failed: malformed control flow. Limit type made precise
      with MaxL/MinL

  * JDK-8304074: [JMX] Add an approximation of total bytes allocated on the Java
      heap by the JVM

  * JDK-8313081: MonitoringSupport_lock should be unconditionally initialized
    ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

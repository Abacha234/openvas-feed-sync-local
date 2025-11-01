# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.857026");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2025-21502");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-21 21:15:15 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-02-04 05:00:10 +0000 (Tue, 04 Feb 2025)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2025:0338-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0338-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EC4FA6VN4EGPE4KWYLPMGJ64XQFZWDHD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2025:0338-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-11-openjdk fixes the following issues:

  Upgrade to upstream tag jdk-11.0.26+4 (January 2025 CPU)

  Security fixes:

    * CVE-2025-21502: Enhance array handling (JDK-8330045, bsc#1236278)

  Other changes:

    * JDK-8224624: Inefficiencies in CodeStrings::add_comment cause - timeouts
    * JDK-8225045: javax/swing/JInternalFrame/8146321//JInternalFrameIconTest.java
      fails on linux-x64
    * JDK-8232367: Update Reactive Streams to 1.0.3 -- tests only
    * JDK-8247706: Unintentional use of new Date(year...) with absolute year
    * JDK-8299254: Support dealing with standard assert macro
    * JDK-8303920: Avoid calling out to python in DataDescriptorSignatureMissing
      test
    * JDK-8315936: Parallelize gc/stress/TestStressG1Humongous.java test
    * JDK-8316193: jdk/jfr/event/oldobject/TestListenerLeak.java
      java.lang.Exception: Could not find leak
    * JDK-8328300: Convert PrintDialogsTest.java from Applet to main program
    * JDK-8328642: Convert applet test MouseDraggedOutCauseScrollingTest.html to
      main
    * JDK-8334332: TestIOException.java fails if run by root
    * JDK-8335428: Enhanced Building of Processes
    * JDK-8335801: [11u] Backport of 8210988 to 11u removes gcc warnings
    * JDK-8335912, JDK-8337499: Add an operation mode to the jar command when
      extracting to not overwriting existing files
    * JDK-8336564: Enhance mask blit functionality redux
    * JDK-8338402: GHA: some of bundles may not get removed
    * JDK-8339082: Bump update version for OpenJDK: jdk-11.0.26
    * JDK-8339180: Enhanced Building of Processes: Follow-on Issue
    * JDK-8339470: [17u] More defensive fix for 8163921
    * JDK-8339637: (tz) Update Timezone Data to 2024b
    * JDK-8339644: Improve parsing of Day/Month in tzdata rules
    * JDK-8339803: Acknowledge case insensitive unambiguous keywords in tzdata
      files
    * JDK-8340552: Harden TzdbZoneRulesCompiler against missing zone names
    * JDK-8340671: GHA: Bump macOS and Xcode versions to macos-12 and XCode 13.4.1
    * JDK-8340815: Add SECURITY.md file
    * JDK-8342426: [11u] javax/naming/module/RunBasic.java javac compile fails
    * JDK-8342629: [11u] Properly message out that shenandoah is disabled
    * JDK-8347483: [11u] Remove designator DEFAULT_PROMOTED_VERSION_PRE=ea for
      release 11.0.26");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

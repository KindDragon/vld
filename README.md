# Visual Leak Detector [![Build status](https://ci.appveyor.com/api/projects/status/0kvft8un16e80toj/branch/master?svg=true)](https://ci.appveyor.com/project/KindDragon/vld/branch/master) <a href="https://www.paypal.com/cgi-bin/webscr?cmd=_donations&amp;business=N3QTYHP9LH6UY&amp;lc=GB&amp;item_name=Visual%20Leak%20Detector&amp;currency_code=USD&amp;bn=PP%2dDonationsBF%3abtn_donate_SM%2egif%3aNonHosted" target="_blank"><img src="https://img.shields.io/badge/paypal-donate-yellow.svg" alt="PayPal donate button" /></a>

## Introduction

Visual C++ provides built-in memory leak detection, but its capabilities are minimal at best. This memory leak detector was created as a free alternative to the built-in memory leak detector provided with Visual C++. Here are some of Visual Leak Detector's features, none of which exist in the built-in detector:

*   Provides a complete stack trace for each leaked block, including source file and line number information when available.
*   Detects most, if not all, types of in-process memory leaks including COM-based leaks, and pure Win32 heap-based leaks.
*   Selected modules (DLLs or even the main EXE) can be excluded from leak detection.
*   Provides complete data dumps (in hex and ASCII) of leaked blocks.
*   Customizable memory leak report: can be saved to a file or sent to the debugger and can include a variable level of detail.

Other after-market leak detectors for Visual C++ are already available. But most of the really popular ones, like Purify and BoundsChecker, are very expensive. A few free alternatives exist, but they're often too intrusive, restrictive, or unreliable. Visual Leak Detector is currently the only freely available memory leak detector for Visual C++ that provides all of the above professional-level features packaged neatly in an easy-to-use library.

Visual Leak Detector is [licensed][3] free of charge as a service to the Windows developer community. If you find it to be useful and would like to just say "Thanks!", or you think it stinks and would like to say "This thing sucks!", please feel free to [drop us a note][1]. Or, if you'd prefer, you can [contribute a small donation][2]. Both are very appreciated.

## Documentation

Read the documentation at [https://github.com/KindDragon/vld/wiki](https://github.com/KindDragon/vld/wiki)

## Contributing

We encourage developers who've added their own features, or fixed bugs they've found, to contribute to the project. The full version-controlled source tree is available publicly via Git at the URL below. Feel free to clone from this URL and submit patches for consideration for inclusion in future versions. You can also issue pull requests for changes that you've made and would like to share.

* [Source code](https://github.com/KindDragon/vld)

Copyright © 2005-2017 VLD Team

 [1]: https://github.com/KindDragon/vld/wiki
 [2]: https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=N3QTYHP9LH6UY&lc=GB&item_name=Visual%20Leak%20Detector&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donate_SM%2egif%3aNonHosted
 [3]: https://github.com/KindDragon/vld/blob/master/COPYING.txt

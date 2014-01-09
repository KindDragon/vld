# Visual Leak Detector

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

Read the documentation at [http://vld.codeplex.com/documentation](http://vld.codeplex.com/documentation)

## Contributing

We encourage developers who've added their own features, or fixed bugs they've found, to contribute to the project. The full version-controlled source tree is available publicly via Git at the URL below. Feel free to clone from this URL and submit patches for consideration for inclusion in future versions. You can also issue pull requests for changes that you've made and would like to share.

* [Source code at Codeplex](http://vld.codeplex.com/SourceControl/BrowseLatest)
* [Source code at GitHub](https://github.com/KindDragon/vld)

Copyright © 2005-2014 VLD Team

 [1]: http://vld.codeplex.com/discussions
 [2]: https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=N3QTYHP9LH6UY&lc=GB&item_name=Visual%20Leak%20Detector&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donate_SM%2egif%3aNonHosted
 [3]: http://vld.codeplex.com/license

[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/KindDragon/vld/trend.png)](https://bitdeli.com/free "Bitdeli Badge")


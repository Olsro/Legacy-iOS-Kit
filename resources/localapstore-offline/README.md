# LocalAPStore offline product catalogue

This is a MobileSubstrate companion bundled **inside an updated LocalIAPStore package**. It addresses a specific failure that LocalIAPStore does not cover: an archived game may request `SKProduct` metadata from the defunct App Store before it attempts a local transaction. The reusable component supplies that metadata from the exact identifiers supplied by the app. It does **not** install content or fabricate a transaction. It also filters duplicate local transaction callbacks and corrects the identity fields in LocalIAPStore's known hard-coded legacy receipt template.

`AutomaticProducts` discovers product identifiers from `SKProductsRequest` for third-party apps installed under `/var/mobile/Applications/`. It does not run in Apple/system processes. The optional `ExcludedBundles` array can disable the automatic path for a particular app. App-specific entries can use `ProductIDs` (a dictionary mapping product identifier to display title) and/or `CatalogPlists` (relative paths inside the app bundle to property lists containing an `Identifiers` dictionary). A request is intercepted only when **all** requested identifiers can be represented; otherwise it follows StoreKit's original path. Automatically generated titles are derived from the identifier's last component. Prices are offline placeholders (`0.00` in the current locale), not historical App Store prices. Metadata discovery alone does not mark purchases complete.

For non-Pinball apps, a StoreKit observer guard discards unnumbered or repeated `purchased` callbacks while preserving the first numbered transaction. This addresses repeated callbacks observed with LocalIAPStore 1.4-2, but does not yet resolve multiple credits inside every game (Subway Surfers remains under investigation). When the original LocalIAPStore receipt contains its recognizable hard-coded Cut the Rope product and bundle, the companion replaces only `product-id`, `bid`, and transaction IDs with the current transaction identity. It does not create a valid Apple signature. Unknown receipt formats pass through unchanged.

Pinball HD 2.37 includes `Tables_iPhone.plist` and `Tables.plist`; the supplied configuration reads table IDs from those files, including Dream Land (`Fantasy`) and Street Racing (`DragRacing`). Its one batch request also contains seven option/pack product IDs not described by these table files; they are listed explicitly in `ProductIDs`. The actual table resources are bundled with the installed app. The companion still needs functional local transaction handling from LocalIAPStore to persist entitlements.

Pinball HD has one additional, game-specific issue: after LocalIAPStore reports a purchased transaction, its `VerificationController` waits for legacy online receipt verification and does not complete the purchase. The Pinball adapter in this companion accepts only `purchased` (`SKPaymentTransactionStatePurchased`) transactions whose product ID is in the configured catalogue, and calls the game's existing completion path. It does not mark a product as purchased before a StoreKit transaction is delivered. This adapter is not applied to other games.

Jetpack Joyride 1.4.1 emits two unnumbered `purchased` callbacks followed by one numbered callback for a single payment. Its specialized observer guard remains as a compatibility fallback; the generic guard now applies before it. A 20,000-coin purchase and a separate 50,000-coin purchase each credited exactly once on the test iPod. Ski Safari 1.5.4.0006 also completed local purchases after duplicate callbacks were removed and the hard-coded receipt identity was corrected.

Mega Jump requires an explicit currency in the synthetic product's `priceLocale`; the companion derives `@currency=CODE` from the device locale. This keeps its catalogue initialization from crashing and was validated through one purchase. Zombie Tsunami's legacy verifier accepts the repaired local receipt but receives `{}` from its defunct remote validation path. Only for that app, and only after a matching numbered local transaction supplied a repaired receipt, the companion passes `{"status":0}` to the game's existing response parser when the response is exactly `{}`. The double-coin entitlement was activated in a live test. This is a local compatibility response, not Apple or server verification.

To build armv7/iOS 5.1.1 and arm64/iOS 7 slices, obtain a compatible universal `CydiaSubstrate` binary from `/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate` and run:

```sh
sh build.sh /path/to/CydiaSubstrate /path/to/output-directory
```

Build the single upgraded package from the original `localiapstore_1.4-2.deb`:

```sh
python3 package.py /path/to/localiapstore_1.4-2.deb \
    /path/to/output-directory/LocalAPStoreOffline.dylib \
    /path/to/localiapstore_1.4-3+olsro2_iphoneos-arm.deb
```

The original LocalIAPStore payload is retained byte-for-byte; the package adds the companion and its preference file. To disable offline metadata without uninstalling LocalIAPStore, set `AutomaticProducts` to `false` and remove app-specific entries from the catalogue, then relaunch the app. No app data is changed.

`1.4-3+olsro2` lowers the companion's armv7 deployment target from iOS 6.0 to iOS 5.1.1, uses indexed array access for the price locale, and skips subclass registration when the StoreKit superclass is absent. The original LocalIAPStore binary is unchanged (its armv7/armv7s slices target iOS 5.1). The Debian firmware dependency remains `>= 5.1.1`. This is a build target, not confirmation of operation on iOS 5.1.1: the new package needs an on-device test before claiming runtime compatibility. The prior iOS 6 game results above describe the previous package.

This is a compatibility layer for legacy StoreKit and the known LocalIAPStore 1.4-2 receipt template. Apps that verify signatures or receipts with their own servers, use hosted downloads, require nonstandard private `SKProduct` fields, or depend on online accounts may need separate investigation. The arm64 slice builds but has not yet been tested on hardware.

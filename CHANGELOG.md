# Changelog

## [1.4.0](https://github.com/intility/go-jwks/compare/v1.3.0...v1.4.0) (2025-04-30)


### Features

* functional options ([#16](https://github.com/intility/go-jwks/issues/16)) ([ca20f4e](https://github.com/intility/go-jwks/commit/ca20f4eaad9bee29c06ab15ebaff9d4f500e9ac8))

## [1.3.0](https://github.com/intility/go-jwks/compare/v1.2.1...v1.3.0) (2025-04-28)


### Features

* add debug logging option to JWKSFetcher ([#14](https://github.com/intility/go-jwks/issues/14)) ([f549fad](https://github.com/intility/go-jwks/commit/f549fad6e947c86f8d1e8ccf17bb6f665abd343b))

## [1.2.1](https://github.com/intility/go-jwks/compare/v1.2.0...v1.2.1) (2025-04-24)


### Bug Fixes

* assert claimsData to pointer ([#11](https://github.com/intility/go-jwks/issues/11)) ([7f4b760](https://github.com/intility/go-jwks/commit/7f4b760fb12bd7a11452bf46bbe56c9b645e511d))

## [1.2.0](https://github.com/intility/go-jwks/compare/v1.1.0...v1.2.0) (2025-04-23)


### Features

* add claims to context ([45ce10b](https://github.com/intility/go-jwks/commit/45ce10b5af630fe0e6ee7f33d694e5750a8ce8fd))
* add func to extract claims from context ([40b33ea](https://github.com/intility/go-jwks/commit/40b33ea02bffe54e5d0717b53cb88a8b77f722c1))
* add user claims to request context ([3b24fa6](https://github.com/intility/go-jwks/commit/3b24fa61f128d01a392228b0eb7d53170d5c2025))


### Bug Fixes

* add logging to middleware ([ce059aa](https://github.com/intility/go-jwks/commit/ce059aab4cc1c4e87964d59216961972548a50ad))
* add logging to middleware ([be672c5](https://github.com/intility/go-jwks/commit/be672c5d54bf68acbab7fc9a328e9ae02b48f57d))

## [1.1.0](https://github.com/intility/go-jwks/compare/v1.0.0...v1.1.0) (2025-04-01)


### Features

* allow for general oidc discovery documents ([9d667a0](https://github.com/intility/go-jwks/commit/9d667a06caf2b9ab301848f0f38e404bdfc94006))
* make http client customizable ([b0e13ee](https://github.com/intility/go-jwks/commit/b0e13ee40be442c4107991b0b1fac201a45f43ee))


### Bug Fixes

* add check for int overflow ([af7eb78](https://github.com/intility/go-jwks/commit/af7eb7890564ecbed48883a685fcabaeee5a616a))
* check for nil jwks ([40b08b8](https://github.com/intility/go-jwks/commit/40b08b8625392adfb6c4bc5e8208866094654790))
* close resp body ([10bc307](https://github.com/intility/go-jwks/commit/10bc3070fa4935bee3b5e65c717c740ed9d6f554))
* div bugfixes ([adc7dee](https://github.com/intility/go-jwks/commit/adc7dee1ec01689edd7e583c6da95334cfea9512))
* set defaults correctly ([5db5c7e](https://github.com/intility/go-jwks/commit/5db5c7ef66c4a45bc0681cdd7722e45f18e76f74))


### Performance Improvements

* initialize keyfunc once ([68c0601](https://github.com/intility/go-jwks/commit/68c0601a9543646034235aec55c2e434a52db13b))

## 1.0.0 (2025-04-01)


### Features

* initial commit ([07d3436](https://github.com/intility/go-jwks/commit/07d3436c46669a422dc6e5ddd79c65c801194690))

## [1.0.2](https://github.com/intility/go-jwks/compare/v1.0.1...v1.0.2) (2025-03-31)


### Bug Fixes

* force release comment ([a2fc82e](https://github.com/intility/go-jwks/commit/a2fc82e2c76a9f22dd0b78af6418283dfce4d1f4))
* force release comment ([6285b93](https://github.com/intility/go-jwks/commit/6285b93f3d5f9f14ed69ac14ba4f1a53780b817c))

## [1.0.1](https://github.com/intility/go-jwks/compare/v1.0.0...v1.0.1) (2025-03-31)


### Bug Fixes

* Error handing ([26064de](https://github.com/intility/go-jwks/commit/26064debc7c9cc295cedc630d5d87b540b9a305f))
* expose fetcher fields ([bb1a051](https://github.com/intility/go-jwks/commit/bb1a05106aaaf5790c8cce6af97f361c45d1cddf))
* force ([b266610](https://github.com/intility/go-jwks/commit/b266610e5d7a39bbe93f72b358941f3b659a9d3d))
* force ([4e8ab94](https://github.com/intility/go-jwks/commit/4e8ab94b1804db14655513785d6983651c06b65a))
* handle empty base url ([bf4d0dc](https://github.com/intility/go-jwks/commit/bf4d0dce6216410f5a11ce00f6680c9f68df940f))

## 1.0.0 (2025-03-30)


### Features

* add fetch interval opt ([305d850](https://github.com/intility/go-jwks/commit/305d85084119bd24fc1d8c628ee74fa528fabce2))
* add main and refactor ([baf8ba3](https://github.com/intility/go-jwks/commit/baf8ba3ebbe15e52f250f2e97c48a6ae943649d5))
* make parse pub key extendable ([8948b28](https://github.com/intility/go-jwks/commit/8948b28da912d1558e86a50e0257cb0f4641bc0a))


### Bug Fixes

* log format ([8653dad](https://github.com/intility/go-jwks/commit/8653dad1e5a0383abfc2e86d945b18aecd51a7b0))
* remove unused ctx and construct url from base ([3bfba1f](https://github.com/intility/go-jwks/commit/3bfba1fd65597004ecee496ca527144254e3da19))
* reuse http client and fetch on startup ([ff90660](https://github.com/intility/go-jwks/commit/ff90660ea1856c9367b82fb4f530008a9e62f4da))

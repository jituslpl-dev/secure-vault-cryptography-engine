{
  "targets": [
    {
      "target_name": "secure_vault",
      "sources": [
        "src/sha256.cpp",
        "src/aes256.cpp",
        "src/encryption_engine.cpp",
        "src/time_lock.cpp",
        "src/streaming_engine.cpp",
        "src/addon.cpp"
      ],
      "include_dirs": [
        "<!@(node -p \"require('path').dirname(require.resolve('node-addon-api'))\")"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS"
      ],
      "conditions": [
        [
          "OS=='win'",
          {
            "libraries": [],
            "msvs_settings": {
              "VCCLCompilerTool": {
                "ExceptionHandling": 1,
                "Optimization": 3,
                "FavorSizeOrSpeed": 2,
                "AdditionalOptions": ["/std:c++14"]
              }
            }
          }
        ],
        [
          "OS=='linux'",
          {
            "cflags_cc": [
              "-O3",
              "-std=c++14",
              "-fexceptions"
            ]
          }
        ],
        [
          "OS=='mac'",
          {
            "cflags_cc": [
              "-O3",
              "-std=c++14",
              "-fexceptions"
            ],
            "xcode_settings": {
              "CLANG_CXX_LANGUAGE_STANDARD": "c++14"
            }
          }
        ]
      ]
    }
  ]
}




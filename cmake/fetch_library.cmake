include(FetchContent)

function(fetch_library name url tag)
  FetchContent_Declare(${name} GIT_REPOSITORY ${url} GIT_TAG ${tag})
  FetchContent_MakeAvailable(${name})
endfunction()
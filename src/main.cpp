#include <iostream>
#include <limits>
#include <memory>
#include <sstream>

#include <libgen.h>
#include <stdio.h>
#include <sys/stat.h>

#ifndef DISABLE_SYSCALL_FILTER
#include <linux/seccomp.h>
#include <sys/prctl.h>
#endif

// /usr/include/poppler/...
#include <DateInfo.h>
#include <FileSpec.h>
#include <FontInfo.h>
#include <Gfx.h>
#include <GlobalParams.h>
#include <PDFDoc.h>
#include <Page.h>
#include <SplashOutputDev.h>
#include <Stream.h>
#include <TextOutputDev.h>
#include <UTF.h>
#include <UnicodeMap.h>
#include <goo/GooList.h>
#include <goo/GooString.h>
#include <goo/gfile.h>
#include <splash/SplashBitmap.h>

#include <msgpack.hpp>

#include "util.hpp"

#include "DumpAsTextDev.h"
#include "DumpPathsAsMsgPackDev.h"

msgpack::packer<std::ostream> packer(&std::cout);

#ifndef DISABLE_SYSCALL_FILTER
#include "seccomp-bpf.h"
#endif
#ifdef ENABLE_SYSCALL_REPORTER
#include "syscall-reporter.h"
#endif

static int install_syscall_filter(void) {
#ifdef DISABLE_SYSCALL_FILTER
  if (true) {
    return 0;
  }
#else
  struct sock_filter filter[] = {
      /* Validate architecture. */
      VALIDATE_ARCHITECTURE,
      /* Grab the system call number. */
      EXAMINE_SYSCALL,
      /* List allowed syscalls. */
      // clang-format off
      ALLOW_SYSCALL(access),
      ALLOW_SYSCALL(fstatfs),
      ALLOW_SYSCALL(readlink),
      ALLOW_SYSCALL(open),
      ALLOW_SYSCALL(close),
      ALLOW_SYSCALL(ioctl),
      ALLOW_SYSCALL(fcntl),
      ALLOW_SYSCALL(getdents64),
      ALLOW_SYSCALL(read),
      ALLOW_SYSCALL(readv),
      ALLOW_SYSCALL(pread64),
      ALLOW_SYSCALL(write),
      ALLOW_SYSCALL(writev),
      ALLOW_SYSCALL(lseek),
      ALLOW_SYSCALL(futex),
      ALLOW_SYSCALL(time),
      ALLOW_SYSCALL(clock_gettime),
      ALLOW_SYSCALL(gettimeofday),
      ALLOW_SYSCALL(fstat),
      ALLOW_SYSCALL(stat),
      ALLOW_SYSCALL(mmap),
      ALLOW_SYSCALL(munmap),
      ALLOW_SYSCALL(madvise),
      ALLOW_SYSCALL(mremap),
      ALLOW_SYSCALL(brk),
      ALLOW_SYSCALL(exit),
      ALLOW_SYSCALL(exit_group),
      KILL_PROCESS,
      // clang-format on
  };

#ifdef ENABLE_SYSCALL_REPORTER
  install_syscall_reporter();
#endif

  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("prctl(NO_NEW_PRIVS)");
    exit(99);
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
    perror("prctl(SECCOMP)");
    exit(99);
  }
  return 0;
#endif // else branch of #ifdef DISABLE_SYSCALL_FILTER
}

class Options {
public:
  std::string filename;
  int start, end;
  bool meta_only;
  bool bitmap;
  bool font_info;
  bool xfa;
  bool embedded_files;

  Options()
      : filename(""), start(0), end(0), meta_only(false), bitmap(false),
        font_info(false), xfa(false), embedded_files(false) {}

  bool range_specified() const { return start != 0 && end != 0; }

  int page_count() const {
    // Note: range is inclusive on the right.
    return end - start + 1;
  }
};

static std::string fmt(const Object &o, UnicodeMap *uMap) {
  if (!o.isString())
    return "<not string>";

  auto s = o.getString();

  char buf[9];
  Unicode *u;
  auto len = TextStringToUCS4(s, &u);

  std::string out;
  out.reserve(static_cast<size_t>(len));

  for (auto i = 0; i < len; i++) {
    auto n = uMap->mapUnicode(u[i], buf, sizeof(buf));
    out.append(buf, n);
  }

  return out;
}

static const char *fontTypeNames[] = {
    "unknown",     "Type 1",           "Type 1C",       "Type 1C (OT)",
    "Type 3",      "TrueType",         "TrueType (OT)", "CID Type 0",
    "CID Type 0C", "CID Type 0C (OT)", "CID TrueType",  "CID TrueType (OT)"};

void dump_font_info(PDFDoc *doc) {
  FontInfoScanner scanner(doc, 0);
  GooList *fonts = scanner.scan(doc->getNumPages());

  if (!fonts) {
    packer.pack_nil();
    return;
  }

  packer.pack_array(fonts->getLength());

  for (int i = 0; i < fonts->getLength(); ++i) {
    auto font = reinterpret_cast<FontInfo *>(fonts->get(i));

    packer.pack_map(6);

    packer.pack("Name");
    packer.pack(font->getName() ? font->getName()->getCString() : "[none]");

    packer.pack("Type");
    packer.pack(fontTypeNames[font->getType()]);

    packer.pack("Encoding");
    packer.pack(font->getEncoding()->getCString());

    packer.pack("Embedded");
    packer.pack(font->getEmbedded());

    packer.pack("Subset");
    packer.pack(font->getSubset());

    packer.pack("ToUnicode");
    packer.pack(font->getToUnicode());
  }
}

void pack_stream_content(Stream *stream) {
  GooString content;

  stream->reset();
  stream->fillGooString(&content);
  stream->close();

  packer.pack_bin(content.getLength());
  packer.pack_bin_body(content.getCString(), content.getLength());
}

void pack_string(GooString *string) {
  if (!string || string->getLength() <= 0)
    packer.pack_nil();
  else
    packer.pack(string->getCString());
}

void dump_meta_xfa(Catalog *catalog, UnicodeMap *uMap) {
  auto xfa = catalog->getAcroForm()->dictLookup("XFA");

  if (xfa.isStream()) {
    pack_stream_content(xfa.getStream());
  } else {
    packer.pack_map(xfa.arrayGetLength() / 2);
    for (int i = 0; i < xfa.arrayGetLength() - 1; i += 2) {
      const auto key = xfa.arrayGet(i);
      const auto value = xfa.arrayGet(i + 1);

      if (!key.isString() || (!value.isString() && !value.isStream())) {
        packer.pack_uint32(i / 2);
        packer.pack_nil();
        continue;
      }
      packer.pack(fmt(key, uMap));
      if (value.isString()) {
        packer.pack(fmt(value, uMap));
      } else {
        pack_stream_content(value.getStream());
      }
    }
  }
}

void dump_meta_embedded_files(Catalog *catalog) {
  packer.pack_array(catalog->numEmbeddedFiles());
  for (int i = 0; i < catalog->numEmbeddedFiles(); i++) {
    FileSpec *spec = catalog->embeddedFile(i);
    EmbFile *file = spec->getEmbeddedFile();

    packer.pack_array(6);
    pack_string(spec->getFileName());
    pack_string(spec->getDescription());
    pack_string(file->mimeType());
    pack_string(file->createDate());
    pack_string(file->modDate());
    pack_stream_content(file->stream());
  }
}

void dump_document_meta(const std::string filename, PDFDoc *doc,
                        UnicodeMap *uMap, const Options &options) {
  Catalog *catalog = doc->getCatalog();
  std::map<std::string, std::string> m;

  auto info = doc->getDocInfo();
  if (info.isDict()) {
    auto dict = info.getDict();

    for (int i = 0; i < dict->getLength(); i++) {
      m[dict->getKey(i)] = fmt(dict->getVal(i), uMap);
    }
  }

  // Use packer.pack_map rather than pack(m) so we can write pages as an
  // integer.
  packer.pack_map(5 + m.size());

  packer.pack("FileName");
  packer.pack(basename(const_cast<char *>(filename.c_str())));

  packer.pack("Pages");
  packer.pack_fix_int64(doc->getNumPages());

  packer.pack("FontInfo");
  if (options.font_info) {
    dump_font_info(doc);
  } else {
    packer.pack_nil();
  }

  packer.pack("XFA");
  if (options.xfa && catalog->getFormType() == Catalog::FormType::XfaForm) {
    dump_meta_xfa(catalog, uMap);
  } else {
    packer.pack_nil();
  }

  packer.pack("EmbeddedFiles");
  if (options.embedded_files) {
    dump_meta_embedded_files(catalog);
  } else {
    packer.pack_nil();
  }

  for (auto i : m) {
    packer.pack(i.first);
    packer.pack(i.second);
  }
}

void TextPageDecRef(TextPage *text_page) { text_page->decRefCnt(); }

typedef std::unique_ptr<TextPage, decltype(&TextPageDecRef)> TextPagePtr;

TextPagePtr page_to_text_page(Page *page) {
  auto dev = std::make_unique<TextOutputDev>(nullptr, gTrue, 0, gFalse, gFalse);

  auto gfx = std::unique_ptr<Gfx>(
      page->createGfx(dev.get(), 72.0, 72.0, 0, gFalse, /* useMediaBox */
                      gTrue,                            /* Crop */
                      -1, -1, -1, -1, gFalse,           /* printing */
                      NULL, NULL));

  page->display(gfx.get());
  dev->endPage();

  return TextPagePtr(dev->takeText(), TextPageDecRef);
}

int count_glyphs(GooList **lines, int n_lines) {
  int total_glyphs = 0;

  for (int i = 0; i < n_lines; i++) {
    auto *words = lines[i];
    total_glyphs += words->getLength() - 1; // spaces
    for (int j = 0; j < words->getLength(); j++) {
      auto *x = reinterpret_cast<TextWordSelection *>(words->get(j));
      auto *word = reinterpret_cast<TextWord *>(x->getWord());
      total_glyphs += word->getLength();
    }
  }
  return total_glyphs;
}

void dump_glyphs(GooList **lines, int n_lines) {
  // Lines
  for (int i = 0; i < n_lines; i++) {
    GooList *line_words = lines[i];

    // Words
    for (int j = 0; j < line_words->getLength(); j++) {
      auto word_sel = reinterpret_cast<TextWordSelection *>(line_words->get(j));
      TextWord *word = word_sel->getWord();

      // Glyphs
      for (int k = 0; k < word->getLength(); k++) {
        double x1, y1, x2, y2;
        word->getCharBBox(k, &x1, &y1, &x2, &y2);

        auto rect = std::make_tuple(x1, y1, x2, y2);
        packer.pack(std::make_tuple(rect, toUTF8(word, k)));
      }

      double x1, y1, x2, y2;
      double x3, y3, x4, y4;
      word->getBBox(&x1, &y1, &x2, &y2);

      // Spaces
      if (j < line_words->getLength() - 1) {
        auto word_sel =
            reinterpret_cast<TextWordSelection *>(line_words->get(j + 1));
        word_sel->getWord()->getBBox(&x3, &y3, &x4, &y4);
        // space is from one word to other and with the same height as
        // first word.

        x1 = x2;
        // y1 = y1; (implicit)
        x2 = x3;
        // y2 = y2; (implicit)

        auto rect = std::make_tuple(x1, y1, x2, y2);
        packer.pack(std::make_tuple(rect, " "));
      }
    }
  }
}

void dump_page_glyphs(Page *page) {
  auto text = page_to_text_page(page);

  const auto inf = std::numeric_limits<double>::infinity();

  PDFRectangle whole_page(-inf, -inf, inf, inf);

  int n_lines;
  auto deleter = [&](GooList **lines) {
    for (int i = 0; i < n_lines; i++) {
      deleteGooList(lines[i], TextWordSelection);
    }
    gfree(lines);
  };
  auto word_list = std::unique_ptr<GooList *, decltype(deleter)>(
      text->getSelectionWords(&whole_page, selectionStyleGlyph, &n_lines),
      deleter);

  int total_glyphs = count_glyphs(word_list.get(), n_lines);

  packer.pack_array(total_glyphs);
  dump_glyphs(word_list.get(), n_lines);
}

void dump_page_paths(Page *page) {
  auto dev = std::make_unique<DumpPathsAsMsgPackDev>();

  auto gfx = std::unique_ptr<Gfx>(
      page->createGfx(dev.get(), 72.0, 72.0, 0, gFalse, /* useMediaBox */
                      gTrue,                            /* Crop */
                      -1, -1, -1, -1, gFalse,           /* printing */
                      NULL, NULL));

  page->display(gfx.get());
  dev->endPage();

  dev->pack(std::cout);
}

void dump_page_bitmap(Page *page) {
  SplashColor paperColor;
  paperColor[0] = 255;
  paperColor[1] = 255;
  paperColor[2] = 255;
  paperColor[3] = 255;

  auto mode = splashModeMono8;
  const auto n_channels = 1;
  // If RGB is desired.
  // auto mode = splashModeRGB8;
  // const auto n_channels = 3;

  auto dev = std::make_unique<SplashOutputDev>(mode, 4, gFalse, paperColor,
                                               gTrue, splashThinLineShape);

  dev->setFontAntialias(true);
  dev->setVectorAntialias(true);
  dev->startDoc(page->getDoc());

  page->display(dev.get(),
                // TODO(pwaller): Parameterize resolution.
                72.0 / 8, 72.0 / 8,
                0,      // rotate
                gFalse, /* useMediaBox */
                gFalse, /* Crop */
                gFalse, /* printing */
                NULL, NULL);

  auto bitmap = dev->getBitmap();

  auto data = reinterpret_cast<char *>(bitmap->getDataPtr());

  packer.pack_array(2);
  packer.pack(std::make_tuple(bitmap->getWidth(), bitmap->getHeight()));

  const size_t amount = n_channels * bitmap->getWidth() * bitmap->getHeight();

  packer.pack_bin(amount);
  for (int i = 0; i < bitmap->getHeight(); i++) {
    packer.pack_bin_body(data, bitmap->getWidth() * n_channels);
    data += bitmap->getRowSize();
  }
}

void dump_page(Page *page, const Options &options) {
  int n = 3;

  if (options.bitmap) {
    n++;
  }

  packer.pack_map(n);

  packer.pack("Size");
  packer.pack(std::make_tuple(page->getMediaWidth(), page->getMediaHeight()));

  packer.pack("Glyphs");
  dump_page_glyphs(page);

  packer.pack("Paths");
  dump_page_paths(page);

  if (options.bitmap) {
    packer.pack("Bitmap");
    dump_page_bitmap(page);
  }
}

void dump_document(PDFDoc *doc, const Options &options) {
  // Pages are one-based in this API. Beware, 0 based elsewhere.
  for (int i = options.start; i <= options.end; i++) {
    dump_page(doc->getPage(i), options);
  }
}

BaseStream *open_file(const std::string filename) {
  GooString goo_filename(filename.c_str());
  auto file = GooFile::open(&goo_filename);
  if (file == NULL) {
    std::cerr << "Failed to open " << filename << std::endl;
    exit(5);
  }
  Object obj;
  return new FileStream(file, 0, gFalse, file->size(), Object(objNull));
}

std::string parse_page_range(std::string value, Options *options) {
  uint8_t c;

  std::istringstream stream(value);
  stream >> options->start >> c >> options->end;

  auto negative = options->start < 1 || options->end < options->start;

  // Must parse whole value.
  if (c != '-' || stream.bad() || !stream.eof() || negative) {
    options->start = options->end = 0;
    return "invalid format for pages: specify like 1-10";
  }

  return "";
}

bool file_exists(std::string name) {
  struct stat buffer;
  return (stat(name.c_str(), &buffer) == 0);
}

std::string parse_options(int argc, char *argv[], Options *options) {
  for (int i = 1; i < argc; ++i) {
    char const *arg = argv[i];

    if ((arg[0] == '-') && (strcmp(arg, "-") != 0)) {
      ++arg;
      if (arg[0] == '-') {
        // Accept -arg and --arg
        ++arg;
      }
      char *parameter = const_cast<char *>(strchr(arg, '='));
      if (parameter) {
        *parameter++ = 0;
      }

      if (strcmp(arg, "pages") == 0) {
        if (parameter == nullptr) {
          return "--pages must be specified as --pages=a-b";
        }
        auto err = parse_page_range(parameter, options);
        if (err != "") {
          return err;
        }
      } else if (strcmp(arg, "meta-only") == 0) {
        options->meta_only = true;
      } else if (strcmp(arg, "bitmap") == 0) {
        options->bitmap = true;
      } else if (strcmp(arg, "font-info") == 0) {
        options->font_info = true;
      } else if (strcmp(arg, "xfa") == 0) {
        options->xfa = true;
      } else if (strcmp(arg, "embedded-files") == 0) {
        options->embedded_files = true;
      } else {
        if (file_exists(arg) && options->filename == "") {
          // It's a filename.
          options->filename = arg;
          continue;
        }
        return std::string("unknown parameter specified: ") + arg;
      }
    } else if (options->filename == "") {
      options->filename = arg;
    } else {
      return std::string("unknown parameter specified: ") + arg;
    }
  }

  if (options->filename == "") {
    return "no input file specified";
  }

  return "";
}

void usage() {
  std::cerr << "usage: pdf2msgpack [--bitmap] [--font-info] [--meta-only] "
               "[--xfa] [--embedded-files] [--pages=a-b] <filename>"
            << std::endl;
}

int main(int argc, char *argv[]) {

  Options options;
  auto err = parse_options(argc, argv, &options);
  if (err != "") {
    std::cerr << "Error: " << err << std::endl;
    usage();
    return 1;
  }

  install_syscall_filter();

  auto file = open_file(options.filename);

  if (!globalParams) {
    globalParams = new GlobalParams("/usr/share/poppler");
  }

  UnicodeMap *uMap;
  if (!(uMap = globalParams->getTextEncoding())) {
    exit(127);
  }

  std::unique_ptr<PDFDoc> doc(new PDFDoc(file));
  if (!doc) {
    std::cerr << "Problem loading document." << std::endl;
    exit(64);
  }

  if (!doc->isOk()) {
    std::cerr << "Failed to open: " << doc->getErrorCode() << std::endl;
    exit(63);
  }

  if (!options.range_specified()) {
    options.start = 1;
    options.end = doc->getNumPages();
  } else if (options.start > doc->getNumPages() ||
             options.end > doc->getNumPages()) {
    std::cerr << "Error: specified page range"
              << " (" << options.start << " - " << options.end << ")"
              << " exceeds document length"
              << " (" << doc->getNumPages() << ")" << std::endl;
    usage();
    exit(1);
  }

  // This version number should be incremented whenever the output format
  // is changed in a way which will break existing parsers.
  const int output_format_version = 1;
  packer.pack_uint32(output_format_version);

  dump_document_meta(options.filename, doc.get(), uMap, options);
  if (options.meta_only) {
    return 0;
  }

  dump_document(doc.get(), options);
}

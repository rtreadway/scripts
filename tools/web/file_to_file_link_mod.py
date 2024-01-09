from bs4 import BeautifulSoup
import argparse


def prep_remap_base(old_links_file, new_links_file):
    old_suffix = '?src=contextnavpagetreemode'
    newD = {}
    
    with open(new_links_file, 'r') as new_text:
        line = new_text.readline()
        while line:
            page_string = line.split('/')[-1]
            newD[page_string.strip()] = {
                "newURL": line.strip()
            }
            line = new_text.readline()

    with open(old_links_file, 'r') as old_text:
        line = old_text.readline()
        while line:
            if line.strip().endswith(old_suffix):
                line = line.strip().replace(old_suffix, '')
                page_string = line.split('/')[5]
                if page_string in newD.keys():
                    newD[page_string]["replacement"] = True
                    newD[page_string]["oldURL"] = line
            line = old_text.readline()
    return newD

def reprocess_bookmarks(bkmk_html_file, dataD, output_path):
    substrings = ['https://jira.collegeboard.org/browse', 'https://confluence.collegeboard.org/display']
    substring_map = {
        'https://jira.collegeboard.org/browse': 'https://collegeboard.atlassian.net/browse'
    }
    output_path = output_path if output_path else 'bookmarks_output.html'
    
    with open(bkmk_html_file, 'r') as bookmarks:
        with open(output_path, 'w') as out:
            line = bookmarks.readline()
            while line:
                for substring in substrings:
                    if substring in line.strip():
                        if line.find(substrings[0]) > 0:
                            line = line.replace(substrings[0], substring_map[substrings[0]])
                            out.write(line)
                        elif line.find(substrings[1]) > 0:
                            soup = BeautifulSoup(line.strip(), 'html.parser')
                            link = soup.find('a').get('href')
                            page_string = link.split('/')[5]
                            data_map = dataD.get(page_string, None)
                            if data_map:
                                line = line.replace(link, data_map['newURL'])
                                out.write(line)
                out.write(line)
                line = bookmarks.readline()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='Atlassian Bookmark Remapper')
    
    parser.add_argument('bookmarks_file', help="Bookmarks HTML file")
    parser.add_argument('old_links', help="Plaintext file containing old Confluence Links")
    parser.add_argument('new_links', help="Plaintext file containing new Confluence Links")
    parser.add_argument('--output', '-o', help="output html filepath")
    
    args = parser.parse_args()
    
    dataD = prep_remap_base(args.old_links, args.new_links)
    reprocess_bookmarks(args.bookmarks_file, dataD, args.output)

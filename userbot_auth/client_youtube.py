#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2019-2026 (c) Randy W @xtdevs, @xtsea
#
# from : https://github.com/TeamKillerX
# Channel : @RendyProjects
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import re
import urllib.parse
from urllib.parse import quote_plus

import requests


class YoutubeConfig:
    def __init__(
        self,
        where_cookies: str,
        search_terms: str,
        max_results: int = 5,
        is_cookies: bool = False
    ):
        self.base_url = "https://youtube.com/results?search_query={0}"
        self.where_cookies = where_cookies
        self.search_terms = search_terms
        self.max_results = max_results
        self.is_cookies = is_cookies
        self.videos = self._search()

    def _search(self):
        encoded_search = urllib.parse.quote_plus(self.search_terms)
        response = requests.get(self.base_url.format(encoded_search)).text

        while "ytInitialData" not in response:
            response = requests.get(self.base_url.format(encoded_search)).text

        results = self._parse_html(response)

        if self.max_results is not None and len(results) > self.max_results:
            return results[: self.max_results]

        return results

    def _parse_html(self, response: str):
        results = []
        start = response.index("ytInitialData") + len("ytInitialData") + 3
        end = response.index("};", start) + 1
        json_str = response[start:end]
        data = json.loads(json_str)

        videos = data["contents"]["twoColumnSearchResultsRenderer"]["primaryContents"][
            "sectionListRenderer"
        ]["contents"][0]["itemSectionRenderer"]["contents"]

        for video in videos:
            res = {}
            if "videoRenderer" in video.keys():
                video_data = video.get("videoRenderer", {})
                _id = video_data.get("videoId", None)

                res["id"] = _id
                res["thumbnail"] = f"https://i.ytimg.com/vi/{_id}/hqdefault.jpg"
                res["title"] = (
                    video_data.get("title", {}).get("runs", [[{}]])[0].get("text", None)
                )
                res["channel"] = (
                    video_data.get("longBylineText", {})
                    .get("runs", [[{}]])[0]
                    .get("text", None)
                )
                res["duration"] = video_data.get("lengthText", {}).get("simpleText", 0)
                res["views"] = video_data.get("viewCountText", {}).get(
                    "simpleText", "Unknown"
                )
                res["publish_time"] = video_data.get("publishedTimeText", {}).get(
                    "simpleText", "Unknown"
                )
                res["url_suffix"] = (
                    video_data.get("navigationEndpoint", {})
                    .get("commandMetadata", {})
                    .get("webCommandMetadata", {})
                    .get("url", None)
                )

                results.append(res)
        return results

    def to_dict(self, clear_cache=True) -> list[dict]:
        result = self.videos
        if clear_cache:
            self.videos = []
        return result

    @staticmethod
    def check_url(url: str) -> tuple[bool, str]:
        if "&" in url:
            url = url[: url.index("&")]

        if "?si=" in url:
            url = url[: url.index("?si=")]

        youtube_regex = (
            r"(https?://)?(www\.)?"
            r"(youtube|youtu|youtube-nocookie)\.(com|be)/"
            r'(video|embed|shorts/|watch\?v=|v/|e/|u/\\w+/|\\w+/)?([^"&?\\s]{11})'
        )
        match = re.match(youtube_regex, url)
        if match:
            return True, match.group(6)
        else:
            return False, "Invalid YouTube URL!"

    def song_options(self) -> dict:
        if not self.is_cookies:
            return "You need to enable cookies"
        if not self.where_cookies:
            return "You need to add cookies to the file"
        return {
            "format": "bestaudio",
            "addmetadata": True,
            "key": "FFmpegMetadata",
            "prefer_ffmpeg": True,
            "geo_bypass": True,
            "nocheckcertificate": True,
            "postprocessors": [
                {
                    "key": "FFmpegExtractAudio",
                    "preferredcodec": "mp3",
                    "preferredquality": "480",
                }
            ],
            "cookiefile": where_cookies,
            "outtmpl": "%(id)s",
            "quiet": True,
            "logtostderr": False,
        }

    def video_options(self) -> dict:
        if not self.is_cookies:
            return "You need to enable cookies"
        if not self.where_cookies:
            return "You need to add cookies to the file"
        return {
            "format": "best",
            "addmetadata": True,
            "key": "FFmpegMetadata",
            "prefer_ffmpeg": True,
            "geo_bypass": True,
            "nocheckcertificate": True,
            "postprocessors": [
                {
                    "key": "FFmpegVideoConvertor",
                    "preferedformat": "mp4",
                }
            ],
            "cookiefile": where_cookies,
            "outtmpl": "%(id)s.mp4",
            "quiet": True,
            "logtostderr": False,
      }

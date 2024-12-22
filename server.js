const express = require("express");
const cors = require("cors");
const { google } = require("googleapis");
require("dotenv").config();
const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");
const User = require("./models/User");

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const app = express();

app.use(cors());
app.use(express.json());

const oAuth2Client = new google.auth.OAuth2(
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI
);

connectDB();

app.use("/api/auth", authRoutes);

app.get('/api/auth/user/:email', async (req, res) => {
    const { email } = req.params;
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      res.status(200).json(user);
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  });

  app.post("/api/updatePlaylists", async (req, res) => {
    const { email, playlists } = req.body;
  
    if (!email || !playlists) {
      return res.status(400).json({ message: "Email and playlists are required" });
    }
  
    try {
      const updateResult = await User.findOneAndUpdate(
        { email },
        { $set: { playlists } }, 
        { new: true } 
      );
  
      if (!updateResult) {
        return res.status(404).json({ message: "User not found" });
      }
  
      res.status(200).json({ message: "Playlists updated successfully" });
    } catch (error) {
      console.error("Error updating playlists:", error);
      res.status(500).json({ message: "Failed to update playlists" });
    }
  });

  
app.get("/auth-url", (req, res) => {
  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: "offline",
    scope: ["https://www.googleapis.com/auth/youtube.readonly"],
  });
  res.send({ url: authUrl });
});

app.get("/oauth-callback", async (req, res) => {
  const { code } = req.query;
  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    const redirectUrl = `http://localhost:5173/dashboard?accessToken=${tokens.access_token}`;
    res.redirect(redirectUrl); 
  } catch (error) {
    console.error("Error exchanging code for tokens:", error);
    res.status(500).send("Authentication failed");
  }
});

app.get("/playlists", async (req, res) => {
  const { accessToken } = req.query;
  if (!accessToken) {
    return res.status(400).send("Access token is required");
  }

  try {
    oAuth2Client.setCredentials({ access_token: accessToken });
    const youtube = google.youtube({ version: "v3", auth: oAuth2Client });

    const response = await youtube.playlists.list({
      part: "snippet",
      mine: true,
      maxResults: 10,
    });

    if (!response.data.items || response.data.items.length === 0) {
      return res.status(404).send("No playlists found for this user.");
    }

    res.send(response.data.items);
  } catch (error) {
    console.error("Error fetching playlists:", error);
    res.status(500).send("Failed to fetch playlists");
  }
});

app.get("/playlist-videos", async (req, res) => {
  const { playlistIds, accessToken, playlists } = req.query;

  if (!playlistIds || !Array.isArray(playlistIds)) {
    return res.status(400).send("playlistIds must be an array");
  }

  try {
    oAuth2Client.setCredentials({ access_token: accessToken });
    const youtube = google.youtube({ version: "v3", auth: oAuth2Client });

    const playlistPromises = playlistIds.map(async (playlistId) => {
      try {
        const playlistResponse = await youtube.playlists.list({
          part: "snippet",
          id: playlistId,
        });

        const playlist = playlistResponse.data.items[0];
        if (!playlist) {
          throw new Error(`Playlist not found: ${playlistId}`);
        }

        const videoResponse = await youtube.playlistItems.list({
          part: "snippet,contentDetails",
          playlistId,
          maxResults: 20,
        });

        const videos = videoResponse.data.items.map((item) => ({
          videoId: item.snippet.resourceId.videoId,
          title: item.snippet.title,
          description: item.snippet.description,
          thumbnail: item?.snippet?.thumbnails?.default?.url,
        }));

        return {
          playlistId,
          title: playlist.snippet.title,
          thumbnail: playlist?.snippet?.thumbnails?.default?.url,
          videos,
        };
      } catch (error) {
        console.error(`Error fetching data for playlist ${playlistId}:`, error);
        return null;
      }
    });

    const playlistResults = await Promise.allSettled(playlistPromises);

    const playlistsData = playlistResults
      .filter((result) => result.status === "fulfilled" && result.value)
      .map((result) => result.value);

    res.send({
      message: "Playlists and videos fetched successfully",
      playlists: playlistsData,
    });
  } catch (error) {
    console.error("Error fetching playlist videos:", error);
    res.status(500).send("Failed to fetch playlist videos");
  }
});

app.post("/save-playlists", async (req, res) => {
  const { email, playlists } = req.body;

  if (!email || !playlists || !Array.isArray(playlists)) {
    return res.status(400).send("Email and playlists data are required.");
  }

  try {
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ email, playlists });
    } else {
      user.playlists = playlists;
    }

    await user.save();
    res.send({ message: "Playlists saved successfully!" });
  } catch (error) {
    console.error("Error saving playlists:", error.message);
    res.status(500).send("Failed to save playlists.");
  }
});

app.get("/channel-playlist-videos", async (req, res) => {
  const { channelId, playlistId } = req.query;

  if (!channelId) {
    return res.status(400).send("Channel ID is required");
  }

  if (!playlistId) {
    return res.status(400).send("Playlist ID is required");
  }

  try {
    const youtube = google.youtube({ version: "v3" });

    const response = await youtube.playlistItems.list({
      part: "snippet",
      playlistId: playlistId,
      maxResults: 50,
    });

    if (!response.data.items || response.data.items.length === 0) {
      return res.status(404).send("No videos found in this playlist.");
    }

    const videos = response.data.items.map((item) => ({
      videoId: item.snippet.resourceId.videoId,
      title: item.snippet.title,
      description: item.snippet.description,
      thumbnail: item.snippet.thumbnails.default.url,
    }));

    res.send(videos);
  } catch (error) {
    console.error("Error fetching videos from playlist:", error);
    res.status(500).send("Failed to fetch videos from the playlist");
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

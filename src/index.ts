import express, { Request, Response, NextFunction } from 'express';
import admin from 'firebase-admin';
import path from 'path';

// Firebase Admin SDK の初期化
// ※サービスアカウントキーのパスは、絶対パスに変換して読み込むと安心です
const serviceAccount = require(path.resolve(__dirname, '..', 'service-account-key.json'));

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();

// 認証ミドルウェアの型定義（必要に応じて拡張可能）
interface AuthenticatedRequest extends Request {
  user?: admin.auth.DecodedIdToken;
}

// 認証ミドルウェア
const checkAuth = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const idToken = authHeader.split('Bearer ')[1];
    admin
      .auth()
      .verifyIdToken(idToken)
      .then((decodedToken) => {
        req.user = decodedToken;
        next();
      })
      .catch((error) => {
        console.error('トークンの検証エラー:', error);
        res.status(403).send('認証に失敗しました。');
      });
  } else {
    res.status(403).send('認証トークンが提供されていません。');
  }
};

// 認証が必要なルート例
app.get('/protected', checkAuth, (req: AuthenticatedRequest, res: Response) => {
  const userEmail = req.user?.email || 'ユーザー';
  res.send(`ようこそ ${userEmail} さん！`);
});

// サーバー起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`サーバーがポート ${PORT} で起動しました。`);
});
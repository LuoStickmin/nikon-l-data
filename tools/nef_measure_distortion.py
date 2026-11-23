import cv2, numpy as np, rawpy, sys, os

def measure(nef, jpg, scale=2, verbose=True):
    with rawpy.imread(nef) as raw:
        rgb = raw.postprocess(use_camera_wb=True, half_size=(scale == 2))
    rawg = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    jp = cv2.imread(jpg, cv2.IMREAD_GRAYSCALE)
    jp = cv2.resize(jp, (rawg.shape[1], rawg.shape[0]), interpolation=cv2.INTER_AREA)
    sift = cv2.SIFT_create(nfeatures=20000)
    k1, d1 = sift.detectAndCompute(jp, None)
    k2, d2 = sift.detectAndCompute(rawg, None)
    bf = cv2.BFMatcher()
    m = bf.knnMatch(d1, d2, k=2)
    good = [x for x, y in m if x.distance < 0.75 * y.distance]
    p1 = np.float32([k1[x.queryIdx].pt for x in good])
    p2 = np.float32([k2[x.trainIdx].pt for x in good])
    H, mask = cv2.findHomography(p1, p2, cv2.RANSAC, 3.0)
    inl = mask.ravel().astype(bool)
    p1, p2 = p1[inl], p2[inl]
    h, w = rawg.shape
    diag = np.hypot(w / 2, h / 2)
    best = None
    for dx in range(-40, 41, 10):
        for dy in range(-40, 41, 10):
            cx, cy = w / 2 + dx, h / 2 + dy
            u = (p1[:, 0] - cx) / diag
            v = (p1[:, 1] - cy) / diag
            r = np.hypot(u, v)
            A = np.stack([r, r**3, r**5, r**7], axis=1)
            y = np.hypot(p2[:, 0] - cx, p2[:, 1] - cy) / diag
            coef, _, _, _ = np.linalg.lstsq(A, y, rcond=None)
            rmse = float(np.sqrt(np.mean((A @ coef - y) ** 2)))
            if best is None or rmse < best[0]:
                best = (rmse, cx, cy, coef)
    rmse, cx, cy, coef = best
    return dict(matches=len(good), inliers=int(inl.sum()), rmse=rmse,
                center=(cx, cy), coef=coef)

if __name__ == "__main__":
    for nef, jpg in [(sys.argv[1], sys.argv[2])]:
        r = measure(nef, jpg)
        c = r["coef"]
        print("matches %d inliers %d rmse %.6f center (%.0f,%.0f)"
              % (r["matches"], r["inliers"], r["rmse"], *r["center"]))
        print("ratio = %.6f + %.6f*r^2 + %.6f*r^4 + %.6f*r^6" % tuple(c))
        print("q=%.5f  k(rho^2)=%.6f  k(rho^4)=%.6f  k(rho^6)=%.6f"
              % (1 / c[0] - 1, c[1] / c[0], c[2] / c[0], c[3] / c[0]))
